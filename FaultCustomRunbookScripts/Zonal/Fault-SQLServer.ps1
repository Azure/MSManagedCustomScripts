<#
.SYNOPSIS
    Performs unplanned failover for an Azure SQL Database in an Azure Runbook.

.DESCRIPTION
    This Azure Runbook script triggers an unplanned failover for an Azure SQL Database.
    It accepts a resource ID as input and performs forced failover operation on the database.
    The script includes detailed logging and error handling optimized for Azure Automation.
    
    This script is designed to simulate planned/unplanned outages for resilience testing purposes.
    It performs the following operations:
    1. Authenticates to Azure using Managed Identity
    2. Validates and imports required PowerShell modules
    3. Parses the provided SQL Database resource ID
    4. Executes a forced failover on the target database
    5. Provides comprehensive logging throughout the process

.PARAMETER ResourceIds
    Comma-separated SQL Database resource IDs. Each resource id should be in the format:
    "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Sql/servers/{server-name}/databases/{database-name}"

.PARAMETER SubscriptionToTargetZone
    JSON-serialized dictionary mapping each involved subscription id to the logical availability zone to fault.
    Example: '{"<subscriptionId>":"<zone>","<subscriptionId2>":"<zone2>"}'.
    If a subscription's zone value is empty or missing, every resource in that subscription is still faulted but
    without zone targeting (zone-aware fault routines fall back to acting on the entire resource).
.PARAMETER TargetZone
    Optional fallback logical availability zone applied to every resource when SubscriptionToTargetZone is
    not supplied. Ignored when SubscriptionToTargetZone is provided.

#>

#Requires -Modules Az.Sql, Az.Accounts
#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma-separated SQL Database resource IDs.")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory = $false, HelpMessage = "JSON-serialized dictionary mapping each involved subscription id to the logical availability zone to fault (e.g. '{""sub1"":""1"",""sub2"":""2""}'). When supplied, takes precedence over TargetZone. If a subscription's zone value is empty or missing, every resource in that subscription is still faulted but without zone targeting.")]
    [object]$SubscriptionToTargetZone,

    [Parameter(Mandatory = $false, HelpMessage = "Fallback logical availability zone applied to every resource when SubscriptionToTargetZone is not supplied. Ignored when SubscriptionToTargetZone is provided.")]
    [string]$TargetZone,

    [Parameter(Mandatory=$false, HelpMessage="Dummy parameter, this will be ignored")]
    [ValidateNotNullOrEmpty()]
    [long]$Duration,

    [Parameter(Mandatory=$false, HelpMessage="Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.")]
    [string]$UAMIClientId
)

function Get-ResourceTargets {
    <#
    .SYNOPSIS
        Pairs each resource id with the target zone resolved from caller input.

    .DESCRIPTION
        Resolves the target zone for each resource using one of two inputs:

          1. SubscriptionToTargetZone (preferred) - subscription id -> target zone map.
             Accepted in any of the following shapes:
               * JSON string of the form '{"<subscriptionId>":"<zone>",...}'.
               * A Hashtable / IDictionary (e.g. @{ 'sub' = '1' }).
               * A PSCustomObject deserialised from JSON by the host (this is what
                 Azure Automation produces when its REST API single-decodes a JSON
                 parameter value).
             If a subscription's zone value is empty or missing, the resource is
             STILL faulted but without zone targeting (the empty zone is propagated
             downstream and zone-aware fault routines fall back to acting on the
             entire resource).

          2. TargetZone (fallback) - used only when SubscriptionToTargetZone is
             null/empty. The same zone string is applied to every resource id.

        Allowing both inputs to be empty/null is permitted: an empty target zone is
        propagated for every resource (downstream zone-aware fault routines treat it as
        "no zone targeting" / act on the whole resource; zone-agnostic routines ignore it).
        Throws only if the SubscriptionToTargetZone payload is a string that cannot be
        parsed as JSON, a resource id cannot be parsed, or a resource belongs to a
        subscription that was not supplied in SubscriptionToTargetZone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceIds,

        [Parameter(Mandatory = $false)]
        [object]$SubscriptionToTargetZone,

        [Parameter(Mandatory = $false)]
        [string]$TargetZone
    )

    if ([string]::IsNullOrWhiteSpace($ResourceIds)) {
        throw "ResourceIds parameter is required and cannot be empty."
    }

    $resourceIdList = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $resourceIdList -or $resourceIdList.Count -eq 0) {
        throw "ResourceIds contained no usable entries."
    }

    # Normalise SubscriptionToTargetZone into a Hashtable<sub,zone> regardless of input shape.
    $subscriptionZoneMap = $null
    if ($null -ne $SubscriptionToTargetZone) {
        if ($SubscriptionToTargetZone -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($SubscriptionToTargetZone)) {
                try {
                    $parsedJson = $SubscriptionToTargetZone | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    throw "SubscriptionToTargetZone is not valid JSON: $($_.Exception.Message)"
                }
                if ($null -eq $parsedJson) {
                    throw "SubscriptionToTargetZone JSON deserialized to null."
                }
                $subscriptionZoneMap = ConvertTo-SubscriptionZoneMap -Source $parsedJson
            }
        }
        elseif ($SubscriptionToTargetZone -is [System.Collections.IDictionary] -or
                $SubscriptionToTargetZone -is [psobject]) {
            $subscriptionZoneMap = ConvertTo-SubscriptionZoneMap -Source $SubscriptionToTargetZone
        }
        else {
            throw "SubscriptionToTargetZone has unsupported type '$($SubscriptionToTargetZone.GetType().FullName)'. Expected JSON string, Hashtable, or PSCustomObject."
        }
    }

    $parsed = New-Object System.Collections.Generic.List[object]

    if ($null -ne $subscriptionZoneMap -and $subscriptionZoneMap.Count -gt 0) {
        # Preferred path: per-subscription mapping supplied.
        foreach ($rid in $resourceIdList) {
            if ($rid -notmatch '/subscriptions/([^/]+)/') {
                throw "Invalid resource id '$rid'. Could not extract subscription id."
            }
            $sub = $Matches[1]
            if (-not $subscriptionZoneMap.ContainsKey($sub)) {
                throw "Resource '$rid' belongs to subscription '$sub' but no entry for that subscription was supplied in SubscriptionToTargetZone."
            }
            $parsed.Add([pscustomobject]@{ ResourceId = $rid; TargetZone = $subscriptionZoneMap[$sub] })
        }
    }
    else {
        # Fallback path: single TargetZone applied to all resources.
        # Empty/missing TargetZone is allowed (legacy contract) and propagates as an empty zone
        # string. Downstream zone-aware fault routines treat empty as "no zone targeting" (act on
        # the whole resource / all zoned backends); zone-agnostic routines ignore it.
        $sharedZone = if ([string]::IsNullOrWhiteSpace($TargetZone)) { '' } else { $TargetZone.Trim() }
        foreach ($rid in $resourceIdList) {
            if ($rid -notmatch '/subscriptions/([^/]+)/') {
                throw "Invalid resource id '$rid'. Could not extract subscription id."
            }
            $parsed.Add([pscustomobject]@{ ResourceId = $rid; TargetZone = $sharedZone })
        }
    }

    return ,$parsed.ToArray()
}

function ConvertTo-SubscriptionZoneMap {
    <#
    .SYNOPSIS
        Normalises a Hashtable / IDictionary / PSCustomObject into a Hashtable<sub,zone>.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Source
    )

    $map = @{}

    if ($Source -is [System.Collections.IDictionary]) {
        foreach ($key in $Source.Keys) {
            $sub = if ($null -eq $key) { '' } else { ([string]$key).Trim() }
            if ([string]::IsNullOrWhiteSpace($sub)) {
                throw "SubscriptionToTargetZone contains an empty subscription id key."
            }
            if ($map.ContainsKey($sub)) {
                throw "Duplicate subscription id '$sub' in SubscriptionToTargetZone."
            }
            $rawZone = $Source[$key]
            $zone = if ($null -eq $rawZone) { '' } else { ([string]$rawZone).Trim() }
            $map[$sub] = $zone
        }
    }
    elseif ($Source -is [psobject]) {
        foreach ($prop in $Source.PSObject.Properties) {
            $sub = if ($null -eq $prop.Name) { '' } else { $prop.Name.Trim() }
            if ([string]::IsNullOrWhiteSpace($sub)) {
                throw "SubscriptionToTargetZone contains an empty subscription id key."
            }
            if ($map.ContainsKey($sub)) {
                throw "Duplicate subscription id '$sub' in SubscriptionToTargetZone."
            }
            $rawZone = $prop.Value
            $zone = if ($null -eq $rawZone) { '' } else { ([string]$rawZone).Trim() }
            $map[$sub] = $zone
        }
    }
    else {
        throw "ConvertTo-SubscriptionZoneMap: unsupported source type '$($Source.GetType().FullName)'."
    }

    return $map
}

$functions = {
    #region Functions

    <#
    .SYNOPSIS
        Writes structured log messages for Azure Runbook execution context.

    .DESCRIPTION
        This function provides standardized logging capabilities for Azure Automation Runbooks.
        It formats log messages with timestamps and severity levels, directing them to appropriate
        Azure output streams based on the log level.

    .PARAMETER Message
        The log message to write.

    .PARAMETER Level
        The severity level of the log message. Valid values: INFO, WARNING, ERROR, SUCCESS.
        Default is INFO.

    .EXAMPLE
        Write-Log "Starting operation" "INFO"
        
    .EXAMPLE
        Write-Log "Operation completed successfully" "SUCCESS"
        
    .EXAMPLE
        Write-Log "Warning: Resource not found" "WARNING"
    #>
    function Write-Log {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,
            
            [Parameter(Mandatory = $false)]
            [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
            [string]$Level = "INFO"
        )
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        
        switch ($Level) {
            "INFO"    { Write-Verbose $logEntry }
            "WARNING" { Write-Warning $logEntry }
            "ERROR"   { Write-Error $logEntry }
            "SUCCESS" { Write-Verbose $logEntry }
        }
    }

    <#
    .SYNOPSIS
        Converts an Azure SQL Database resource ID into its components.

    .DESCRIPTION
        This function extracts subscription ID, resource group name, server name, and database name
        from a properly formatted Azure SQL Database resource ID.
        It validates the format and throws an error if the format is invalid.

    .PARAMETER ResourceId
        The Azure resource ID to parse.

    .OUTPUTS
        Returns a hashtable containing:
        - SubscriptionId: The Azure subscription ID
        - ResourceGroup: The resource group name
        - ServerName: The SQL server name
        - DatabaseName: The SQL database name

    .EXAMPLE
        $resourceInfo = ConvertFrom-ResourceId -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.Sql/servers/myserver/databases/mydatabase"
        # Returns: @{SubscriptionId="12345678-1234-1234-1234-123456789012"; ResourceGroup="myRG"; ServerName="myserver"; DatabaseName="mydatabase"}

    .NOTES
        Only supports Azure SQL Database resource IDs.
    #>
    function ConvertFrom-ResourceId {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$ResourceId
        )
        
        if ($ResourceId -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Sql/servers/([^/]+)/databases/([^/]+)") {
            return @{
                SubscriptionId = $Matches[1]
                ResourceGroup = $Matches[2]
                ServerName = $Matches[3]
                DatabaseName = $Matches[4]
            }
        }
        else {
            throw "Invalid resource ID format. Expected format: /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Sql/servers/{server-name}/databases/{database-name}"
        }
    }

    <#
    .SYNOPSIS
        Authenticates to Azure using Managed Identity for Azure Automation context.

    .DESCRIPTION
        This function handles Azure authentication specifically for Azure Automation Runbooks.
        It first checks if an Azure context already exists, and if not, attempts to connect
        using the Managed Identity assigned to the Automation Account.

    .OUTPUTS
        Returns $true if authentication is successful, $false otherwise.

    .EXAMPLE
        if (Connect-ToAzure) {
            Write-Log "Azure authentication successful"
        }

    .NOTES
        This function is designed specifically for Azure Automation environments.
        It requires a Managed Identity to be configured on the Automation Account.
    #>
    function Connect-ToAzure {
        [CmdletBinding()]
        [OutputType([bool])]
        param(
            [string]$ClientId,
            [string]$SubscriptionId
        )
        
        try {
            if ([string]::IsNullOrEmpty($ClientId)) {
                Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
                Connect-AzAccount -Identity -Verbose:$false -ErrorAction Stop | Out-Null
            } 
            else {
                Write-Log "Authenticating to Azure via User-Assigned Managed Identity (ClientId: $ClientId)" "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -Verbose:$false -ErrorAction Stop | Out-Null
            }

            # If a subscription ID is provided, set the context to that subscription immediately
            if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
                Write-Log "Setting subscription context to $SubscriptionId" "INFO"
                Set-AzContext -SubscriptionId $SubscriptionId -Verbose:$false -ErrorAction Stop | Out-Null
            }
            
            $context = Get-AzContext -ErrorAction Stop
            Write-Log "Successfully connected to Azure as $($context.Account.Id) in subscription: $($context.Subscription.Name)" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Failed to authenticate to Azure: $($_.Exception.Message)" "ERROR"
            throw "Azure authentication failed: $($_.Exception.Message)"
        }
    }

    <#
    .SYNOPSIS
        Validates and imports required PowerShell modules for SQL Database operations.

    .DESCRIPTION
        This function checks for the availability of the Az.Sql module and imports it
        if it's available but not currently loaded. This is essential for SQL Database
        operations in Azure Automation environments.

    .OUTPUTS
        Returns $true if the module is available and loaded, $false otherwise.

    .EXAMPLE
        if (Initialize-RequiredModules) {
            Write-Log "All required modules are available"
        }

    .NOTES
        The Az.Sql module must be imported into the Azure Automation Account
        before this function can succeed.
    #>
    function Initialize-RequiredModules {
        [CmdletBinding()]
        [OutputType([bool])]
        param()
        
        try {
            Write-Log "Checking for required Az.Sql module..." "INFO"
            if (-not (Get-Module -Name Az.Sql -ListAvailable 4>$null)) {
                throw "Az.Sql module is not available in this Automation Account"
            }
            
            if (-not (Get-Module -Name Az.Sql)) {
                Write-Log "Az.Sql module found but not loaded. Importing module..." "INFO"
                Import-Module Az.Sql -Force -ErrorAction Stop 4>$null
            }
            
            Write-Log "Az.Sql module is ready" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Failed to initialize required modules: $($_.Exception.Message)" "ERROR"
            throw "Module initialization failed: $($_.Exception.Message)"
        }
    }

    <#
    .SYNOPSIS
        Performs an unplanned failover on an Azure SQL Database.

    .DESCRIPTION
        This function executes a forced failover operation on the specified SQL Database.
        It handles subscription context switching if needed and provides
        detailed logging throughout the process.

    .PARAMETER ResourceGroupName
        The name of the resource group containing the SQL server.

    .PARAMETER ServerName
        The name of the SQL server containing the database.

    .PARAMETER DatabaseName
        The name of the SQL Database to failover.

    .PARAMETER SubscriptionId
        The Azure subscription ID. If provided and different from current context, 
        the function will switch to this subscription.

    .OUTPUTS
        Returns $true if the failover operation is successful, $false otherwise.

    .EXAMPLE
        $success = Invoke-SQLDatabaseFailover -ResourceGroupName "myRG" -ServerName "myserver" -DatabaseName "mydatabase" -SubscriptionId "12345678-1234-1234-1234-123456789012"

    .NOTES
        This operation will cause temporary unavailability of the SQL Database.
        Use with caution, especially in production environments.
        The database must have geo-replication configured for failover to work.
    #>
    function Invoke-SQLDatabaseFailover {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$ResourceGroupName,
            
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$ServerName,
            
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$DatabaseName,
            
            [Parameter(Mandatory = $false)]
            [string]$SubscriptionId
        )
        
        try {
            Write-Log "Initiating unplanned failover for database '$DatabaseName' on server '$ServerName'..." "INFO"
            
            $failoverResult = Invoke-AzSqlDatabaseFailover `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $ServerName `
                -DatabaseName $DatabaseName `
                -ErrorAction Stop
            
            # Invoke-AzSqlDatabaseFailover doesn't return an object on success, but if we reach here, it succeeded
            Write-Log "Successfully initiated failover for database '$DatabaseName'" "SUCCESS"
            return [pscustomobject]@{ IsSuccess = $true; Status = 'Succeeded'; Message = "Failover initiated successfully" }
        }
        catch {
            $errorMessage = "Failed to failover database '$DatabaseName': $($_.Exception.Message)"
            Write-Log $errorMessage "ERROR"
            return [pscustomobject]@{ IsSuccess = $false; Status = 'Failed'; Message = $errorMessage }
        }
    }

    #endregion Functions
}

#region Main Script Execution
# Set VerbosePreference to Continue to see Write-Verbose logs in automation job streams.
# Suppress engine-level module-load verbose noise (PowerShell emits "Loading module"
# and "Importing cmdlet" while $VerbosePreference is Continue, regardless of -Verbose:$false).
# Pre-import Az.Accounts silently, then enable verbose so our own Write-Verbose logs appear.
$VerbosePreference = 'SilentlyContinue'
Import-Module Az.Accounts -ErrorAction Stop
$VerbosePreference = 'Continue'

Write-Verbose "============================================================"
Write-Verbose "AZURE SQL DATABASE FAILOVER SCRIPT"
Write-Verbose "============================================================"
Write-Verbose "Starting SQL Database Failover operation..."
$loggedSubscriptionToTargetZone = if ($null -eq $SubscriptionToTargetZone) { '<null>' } elseif ($SubscriptionToTargetZone -is [string]) { $SubscriptionToTargetZone } else { $SubscriptionToTargetZone | ConvertTo-Json -Compress -Depth 5 }
Write-Verbose "Raw Input: ResourceIds=$ResourceIds; SubscriptionToTargetZone=$loggedSubscriptionToTargetZone; TargetZone=$TargetZone"
$sqlTargets = Get-ResourceTargets -ResourceIds $ResourceIds -SubscriptionToTargetZone $SubscriptionToTargetZone -TargetZone $TargetZone
Write-Verbose "Parsed $($sqlTargets.Count) SQL database target(s)."

# Initial connection check in main thread
try {
    if ($UAMIClientId) {
        Connect-AzAccount -Identity -AccountId $UAMIClientId -Verbose:$false -ErrorAction Stop | Out-Null
    } else {
        Connect-AzAccount -Identity -Verbose:$false -ErrorAction Stop | Out-Null
    }
    $ctx = Get-AzContext -ErrorAction Stop
    Write-Verbose "Initial connection successful as $($ctx.Account.Id) on subscription $($ctx.Subscription.Name)"
} catch {
    throw "Initial Azure authentication failed. Please check Managed Identity configuration. Error: $($_.Exception.Message)"
}

$scriptStart = Get-Date

Write-Verbose "Starting parallel processing of $($sqlTargets.Count) SQL databases"

$functionsScript = $functions.ToString()

$resultsRaw = $sqlTargets | ForEach-Object -Parallel {
    # Set VerbosePreference in the parallel runspace so Write-Verbose logs appear
    # Suppress engine-level module-load verbose noise (PowerShell emits "Loading module"
    # and "Importing cmdlet" while $VerbosePreference is Continue, regardless of -Verbose:$false).
    # Pre-import Az.Accounts silently, then enable verbose so our own Write-Verbose logs appear.
    $VerbosePreference = 'SilentlyContinue'
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Sql -ErrorAction Stop
    $VerbosePreference = 'Continue'
    
    # Define functions in the parallel runspace
    $functionBlock = [scriptblock]::Create($using:functionsScript)
    . $functionBlock
    
    $entry = $_
    $rid = $entry.ResourceId
    $targetZone = $entry.TargetZone
    $targetZoneLabel = if ([string]::IsNullOrWhiteSpace($targetZone)) { '<none - faulting without zone targeting>' } else { $targetZone }
    Write-Verbose "Targeting zone '$targetZoneLabel' for resource $($entry.ResourceId)"
    $start = Get-Date
    $result = [pscustomobject]@{
        ResourceId = $rid
        IsSuccess = $false
        ErrorMessage = $null
        StartTime = $start
        EndTime = $start
        Status = 'FailedToStart'
    }


    try {
        # Parse resource ID first to get the subscription
        $info = ConvertFrom-ResourceId -ResourceId $rid

        # Authenticate and initialize modules in the parallel runspace, passing the target subscription
        Connect-ToAzure -ClientId $using:UAMIClientId -SubscriptionId $info.SubscriptionId | Out-Null
        Initialize-RequiredModules | Out-Null

        $faultResult = Invoke-SQLDatabaseFailover -ResourceGroupName $info.ResourceGroup -ServerName $info.ServerName -DatabaseName $info.DatabaseName -SubscriptionId $info.SubscriptionId
        $end = Get-Date

        $result.IsSuccess = $faultResult.IsSuccess
        $result.ErrorMessage = $faultResult.Message
        $result.EndTime = $end
        $result.Status = $faultResult.Status
    } catch { 
        $result.EndTime = Get-Date
        $result.ErrorMessage = $_.Exception.Message
        $result.Status = 'Failed'
    }
    return $result

}

$resultsRaw = @($resultsRaw | Where-Object { $_ })
$results = @()
$unexpectedOutputs = @()

foreach ($item in $resultsRaw) {
    if ($item -is [pscustomobject] -and $item.PSObject.Properties['ResourceId']) {
        $results += $item
    }
    else {
        $unexpectedOutputs += $item
        Write-Verbose "Captured unexpected output item of type '$($item.GetType().FullName)'."
    }
}

if ($unexpectedOutputs.Count -gt 0) {
    Write-Verbose "Skipping $($unexpectedOutputs.Count) unexpected output item(s) from parallel processing."
}

if ($results.Count -eq 0 -and $unexpectedOutputs.Count -gt 0) {
    Write-Warning "Parallel processing returned no valid result objects. Check unexpected outputs for details."
}

$scriptEnd = Get-Date
$successCount = ($results | Where-Object { $_.IsSuccess }).Count
$failureCount = ($results | Where-Object { -not $_.IsSuccess }).Count
$failureCount += $unexpectedOutputs.Count
$overallStatus = if ($failureCount -eq 0) { 'Success' } elseif ($successCount -gt 0) { 'PartialSuccess' } else { 'Failed' }

$resourceResults = @()
foreach ($r in $results) {
    if (-not $r) { continue }
    $endTime = if ($r.EndTime) { $r.EndTime } elseif ($r.StartTime) { $r.StartTime } else { Get-Date }
    $startTime = if ($r.StartTime) { $r.StartTime } else { $endTime }
    try {
        if ($endTime -isnot [DateTime]) {
            $endTime = [DateTime]::Parse($endTime.ToString(), [System.Globalization.CultureInfo]::InvariantCulture)
        }
        if ($startTime -isnot [DateTime]) {
            $startTime = [DateTime]::Parse($startTime.ToString(), [System.Globalization.CultureInfo]::InvariantCulture)
        }
    } catch {
        $endTime = Get-Date
        $startTime = $endTime
    }
    $durationMs = [int]([Math]::Round((($endTime) - $startTime).TotalMilliseconds))
    $err = $null
    if (-not $r.IsSuccess) { $err = @{ ErrorCode='FailedToFaultResource'; Message=$r.ErrorMessage; Details=$r.ErrorMessage; Category=$r.Status; IsRetryable=$false } }
    $processedAtUtc = $endTime.ToUniversalTime()
    $resourceResults += @{ ResourceId=$r.ResourceId; IsSuccess=$r.IsSuccess; Error=$err; ProcessedAt=$processedAtUtc; ProcessingDurationMs=$durationMs; Metadata=@{ Status=$r.Status } }
}

foreach ($unexpected in $unexpectedOutputs) {
    $details = ($unexpected | Out-String).Trim()
    $resourceResults += @{ ResourceId = $null; IsSuccess = $null; Error = @{ ErrorCode = 'UnexpectedOutput'; Message = if ($details) { $details } else { $unexpected.ToString() }; Details = $details; Category = $null; IsRetryable = $false }; ProcessedAt = (Get-Date).ToUniversalTime(); ProcessingDurationMs = 0; Metadata = @{ Status = $null } }
}

$executionResult = [ordered]@{
    Status=$overallStatus
    ResourceResults=$resourceResults
    SuccessCount=$successCount
    FailureCount=$failureCount
    ExecutionStartTime=$scriptStart.ToUniversalTime()
    ExecutionEndTime=$scriptEnd.ToUniversalTime()
    GlobalError= if ($overallStatus -eq 'Failed') { 'All SQL database failover operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some operations failed.' } else { $null }
}
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Fail the runbook if any resource could not be faulted
if ($failureCount -gt 0) {
    $errorMsg = "Runbook failed: $failureCount out of $($sqlTargets.Count) SQL database(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Verbose "All SQL database failover operations completed successfully."

#endregion Main Script Execution