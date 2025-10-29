<#
.SYNOPSIS
    Performs unplanned restart with failover for Azure PostgreSQL Flexible Servers in an Azure Runbook.

.DESCRIPTION
    This Azure Runbook script triggers an unplanned restart with failover for one or more Azure PostgreSQL Flexible Servers.
    It accepts a comma-separated list of resource IDs as input and performs forced failover operations on each server.
    The script includes detailed logging and error handling optimized for Azure Automation.
    
    This script is designed to simulate planned/unplanned outages for resilience testing purposes.
    It performs the following operations:
    1. Authenticates to Azure using Managed Identity
    2. Validates and imports required PowerShell modules
    3. Parses the provided PostgreSQL server resource IDs
    4. Executes a forced failover restart on each target server
    5. Provides comprehensive logging throughout the process

.PARAMETER ResourceIds
    A comma-separated list of resource IDs for the Azure PostgreSQL Flexible Servers to be restarted with failover.
    Each resource ID should be in the format:
    "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.DBforPostgreSQL/flexibleServers/{server-name}"

.EXAMPLE
    # Example 1: Direct execution with resource IDs
    .\Fault-PGSQL-Server.ps1 -ResourceIds "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.DBforPostgreSQL/flexibleServers/myserver1,/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.DBforPostgreSQL/flexibleServers/myserver2"
    
.NOTES
    Author: Azure DevOps Team
    Date: 2025-09-25
    Version: 2.2 (PS7 Always-Parallel)
    
    Prerequisites:
    - Az.PostgreSQL module must be imported in the Azure Automation account
    - Runbook must run with appropriate permissions (Contributor role on target PostgreSQL servers)
    - Managed Identity or Run As Account must be configured for the Automation Account
    - Target PostgreSQL servers must be Flexible Servers (not Single Servers)
    
    Security Considerations:
    - This script performs destructive operations and should only be used in controlled environments
    - Ensure proper RBAC permissions are in place
    - Consider implementing approval workflows for production environments
    
    Logging:
    - All operations are logged with timestamps and severity levels
    - Logs are written to Azure Automation output streams for monitoring
#>

#Requires -Modules Az.PostgreSQL, Az.Accounts
#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma separated Resource IDs of the Azure PostgreSQL Flexible Servers")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$false, HelpMessage="Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.")]
    [string]$UAMIClientId,

    [Parameter(Mandatory=$false, HelpMessage="Dummy parameter, this will be ignored")]
    [ValidateNotNullOrEmpty()]
    [long]$Duration
)

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
            "INFO"    { Write-Information $logEntry -InformationAction Continue }
            "WARNING" { Write-Warning $logEntry }
            "ERROR"   { Write-Error $logEntry }
            "SUCCESS" { Write-Information $logEntry -InformationAction Continue }
        }
    }

    <#
    .SYNOPSIS
        Converts an Azure PostgreSQL Flexible Server resource ID into its components.

    .DESCRIPTION
        This function extracts subscription ID, resource group name, and server name
        from a properly formatted Azure PostgreSQL Flexible Server resource ID.
        It validates the format and throws an error if the format is invalid.

    .PARAMETER ResourceId
        The Azure resource ID to parse.

    .OUTPUTS
        Returns a hashtable containing:
        - SubscriptionId: The Azure subscription ID
        - ResourceGroup: The resource group name
        - ServerName: The PostgreSQL server name

    .EXAMPLE
        $resourceInfo = ConvertFrom-ResourceId -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.DBforPostgreSQL/flexibleServers/myserver"
        # Returns: @{SubscriptionId="12345678-1234-1234-1234-123456789012"; ResourceGroup="myRG"; ServerName="myserver"}

    .NOTES
        Only supports Azure PostgreSQL Flexible Server resource IDs.
        Single Server format is not supported.
    #>
    function ConvertFrom-ResourceId {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$ResourceId
        )
        
        if ($ResourceId -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.DBforPostgreSQL/flexibleServers/([^/]+)") {
            return @{
                SubscriptionId = $Matches[1]
                ResourceGroup = $Matches[2]
                ServerName = $Matches[3]
            }
        }
        else {
            throw "Invalid resource ID format. Expected format: /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.DBforPostgreSQL/flexibleServers/{server-name}"
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
            [string]$ClientId
        )
        
        try {
            if ([string]::IsNullOrEmpty($ClientId)) {
                Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            } 
            else {
                Write-Log "Authenticating to Azure via User-Assigned Managed Identity (ClientId: $ClientId)" "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -ErrorAction Stop | Out-Null
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
        Validates and imports required PowerShell modules for PostgreSQL operations.

    .DESCRIPTION
        This function checks for the availability of the Az.PostgreSQL module and imports it
        if it's available but not currently loaded. This is essential for PostgreSQL Flexible
        Server operations in Azure Automation environments.

    .OUTPUTS
        Returns $true if the module is available and loaded, $false otherwise.

    .EXAMPLE
        if (Initialize-RequiredModules) {
            Write-Log "All required modules are available"
        }

    .NOTES
        The Az.PostgreSQL module must be imported into the Azure Automation Account
        before this function can succeed.
    #>
    function Initialize-RequiredModules {
        [CmdletBinding()]
        [OutputType([bool])]
        param()
        
        try {
            Write-Log "Checking for required Az.PostgreSQL module..." "INFO"
            if (-not (Get-Module -Name Az.PostgreSQL -ListAvailable)) {
                throw "Az.PostgreSQL module is not available in this Automation Account"
            }
            
            if (-not (Get-Module -Name Az.PostgreSQL)) {
                Write-Log "Az.PostgreSQL module found but not loaded. Importing module..." "INFO"
                Import-Module Az.PostgreSQL -ErrorAction Stop -Force
            }
            
            Write-Log "Az.PostgreSQL module is ready" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Failed to initialize required modules: $($_.Exception.Message)" "ERROR"
            throw "Module initialization failed: $($_.Exception.Message)"
        }
    }

    <#
    .SYNOPSIS
        Performs an unplanned restart with failover on an Azure PostgreSQL Flexible Server.

    .DESCRIPTION
        This function executes a forced failover restart operation on the specified PostgreSQL
        Flexible Server. It handles subscription context switching if needed and provides
        detailed logging throughout the process.

    .PARAMETER ResourceGroupName
        The name of the resource group containing the PostgreSQL server.

    .PARAMETER ServerName
        The name of the PostgreSQL Flexible Server to restart.

    .PARAMETER SubscriptionId
        The Azure subscription ID. If provided and different from current context, 
        the function will switch to this subscription.

    .OUTPUTS
        Returns $true if the restart operation is successful, $false otherwise.

    .EXAMPLE
        $success = Restart-PostgreSQLServerWithFailover -ResourceGroupName "myRG" -ServerName "myserver" -SubscriptionId "12345678-1234-1234-1234-123456789012"

    .NOTES
        This operation will cause temporary unavailability of the PostgreSQL server.
        Use with caution, especially in production environments.
        The operation uses ForcedFailover mode for immediate effect.
    #>
    function Restart-PostgreSQLServerWithFailover {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$ResourceGroupName,
            
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$ServerName,
            
            [Parameter(Mandatory = $false)]
            [string]$SubscriptionId
        )
        
        try {
            Write-Log "Initiating unplanned restart with failover for server '$ServerName' in resource group '$ResourceGroupName'..." "INFO"
            
            Restart-AzPostgreSqlFlexibleServer `
                -ResourceGroupName $ResourceGroupName `
                -Name $ServerName `
                -RestartWithFailover `
                -FailoverMode ForcedFailover `
                -ErrorAction Stop
                
            Write-Log "Successfully initiated failover for server '$ServerName'" "SUCCESS"
            return [pscustomobject]@{ IsSuccess = $true; Status = 'Succeeded'; Message = "Restart with failover initiated successfully" }
        }
        catch {
            $errorMessage = "Failed to restart server '$ServerName' with failover: $($_.Exception.Message)"
            Write-Log $errorMessage "ERROR"
            return [pscustomobject]@{ IsSuccess = $false; Status = 'Failed'; Message = $errorMessage }
        }
    }

    #endregion Functions
}

#region Main Script Execution
# Set InformationPreference to Continue to see Write-Information logs in automation job streams.
$InformationPreference = 'Continue'

Write-Information "============================================================"
Write-Information "AZURE POSTGRESQL FLEXIBLE SERVER FAILOVER SCRIPT"
Write-Information "============================================================"
Write-Information "Starting PostgreSQL Flexible Server Failover operation..."
Write-Information "Raw Input: $ResourceIds"

$pgIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $pgIds -or $pgIds.Count -eq 0) { throw "No valid PostgreSQL resource IDs provided" }
Write-Information "Parsed $($pgIds.Count) PostgreSQL server id(s)."

$scriptStart = Get-Date
$opResults = @()

# Initial connection check in main thread
try {
    Write-Information "Authenticating to Azure..."
    if ($UAMIClientId) {
        Connect-AzAccount -Identity -AccountId $UAMIClientId -ErrorAction Stop | Out-Null
    } else {
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    }
    $ctx = Get-AzContext -ErrorAction Stop
    Write-Information "Initial connection successful as $($ctx.Account.Id) on subscription $($ctx.Subscription.Name)"
} catch {
    throw "Initial Azure authentication failed. Please check Managed Identity configuration. Error: $($_.Exception.Message)"
}

Write-Information "Starting parallel processing of $($pgIds.Count) PostgreSQL servers."

$functionsScript = $functions.ToString()

$opResultsRaw = $pgIds | ForEach-Object -Parallel {
    # Set InformationPreference in the parallel runspace so Write-Information logs appear
    $InformationPreference = 'Continue'
    
    # Define functions in the parallel runspace
    $functionBlock = [scriptblock]::Create($using:functionsScript)
    . $functionBlock

    $rid = $_
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
        # Authenticate and initialize modules in the parallel runspace
        Connect-ToAzure -ClientId $using:UAMIClientId | Out-Null
        Initialize-RequiredModules | Out-Null

        # Parse resource ID
        $info = ConvertFrom-ResourceId -ResourceId $rid

        # Switch subscription context if needed
        $currentSub = (Get-AzContext).Subscription.Id
        if ($info.SubscriptionId -and $currentSub -ne $info.SubscriptionId) {
            Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null
            Write-Log "Switched to subscription $($info.SubscriptionId) for resource $rid" "INFO"
        }

        $faultResult = Restart-PostgreSQLServerWithFailover -ResourceGroupName $info.ResourceGroup -ServerName $info.ServerName -SubscriptionId $info.SubscriptionId
        $end = Get-Date

        $result.IsSuccess = $faultResult.IsSuccess
        $result.ErrorMessage = $faultResult.Message
        $result.EndTime = $end
        $result.Status = $faultResult.Status
    }
    catch {
        $result.EndTime = Get-Date
        $result.ErrorMessage = $_.Exception.Message
        $result.Status = 'Failed'
    }
    return $result
}

$opResultsRaw = @($opResultsRaw | Where-Object { $_ })
$opResults = @()
$unexpectedOutputs = @()

foreach ($item in $opResultsRaw) {
    if ($item -is [pscustomobject] -and $item.PSObject.Properties['ResourceId']) {
        $opResults += $item
    }
    else {
        $unexpectedOutputs += $item
        Write-Information "Captured unexpected output item of type '$($item.GetType().FullName)'." -InformationAction Continue
    }
}

if ($unexpectedOutputs.Count -gt 0) {
    Write-Information "Skipping $($unexpectedOutputs.Count) unexpected output item(s) from parallel processing." -InformationAction Continue
}

if ($opResults.Count -eq 0 -and $unexpectedOutputs.Count -gt 0) {
    Write-Warning "Parallel processing returned no valid result objects. Check unexpected outputs for details."
}


$scriptEnd = Get-Date
$successCount = ($opResults | Where-Object { $_.IsSuccess }).Count
$failureCount = ($opResults | Where-Object { -not $_.IsSuccess }).Count
$failureCount += $unexpectedOutputs.Count
$overallStatus = if ($failureCount -eq 0) { 'Success' } elseif ($successCount -gt 0) { 'PartialSuccess' } else { 'Failed' }

$resourceResults = @()
foreach ($r in $opResults) {
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

$executionResult = [ordered]@{ Status=$overallStatus; ResourceResults=$resourceResults; SuccessCount=$successCount; FailureCount=$failureCount; ExecutionStartTime=$scriptStart.ToUniversalTime(); ExecutionEndTime=$scriptEnd.ToUniversalTime(); GlobalError= if ($overallStatus -eq 'Failed') { 'All PostgreSQL failover operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some failover operations failed.' } else { $null } }
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Fail the runbook if any resource could not be faulted
if ($failureCount -gt 0) {
    $errorMsg = "Runbook failed: $failureCount out of $($pgIds.Count) PostgreSQL server(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Information "All PostgreSQL server failover operations completed successfully." -InformationAction Continue

#endregion Main Script Execution
