<#
.SYNOPSIS
    Performs forced reboot of the primary replica for an Azure Redis Cache in an Azure Runbook.

.DESCRIPTION
    This Azure Runbook script triggers a forced reboot of the primary replica for an Azure Redis Cache.
    It accepts a resource ID as input and performs forced reboot operation on the cache primary replica.
    The script includes detailed logging and error handling optimized for Azure Automation.
    
    This script is designed to simulate planned/unplanned outages for resilience testing purposes.
    It performs the following operations:
    1. Authenticates to Azure using Managed Identity
    2. Validates and imports required PowerShell modules
    3. Parses the provided Redis Cache resource ID
    4. Executes a forced reboot on the primary replica of the target cache
    5. Provides comprehensive logging throughout the process

.PARAMETER ResourceId
    The resource ID for the Azure Redis Cache to be rebooted.
    The resource ID should be in the format:
    "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Cache/redis/{cache-name}"

.EXAMPLE
    # Example 1: Direct execution with resource ID
    .\Fault-RedisCache.ps1 -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.Cache/redis/mycache"
    
.NOTES
    Author: Azure DevOps Team
    Date: 2025-09-19
    Version: 1.3
    
    Prerequisites:
    - Az.RedisCache module must be imported in the Azure Automation account
    - Runbook must run with appropriate permissions (Contributor role on target Redis caches)
    - Managed Identity or Run As Account must be configured for the Automation Account
    - Target Redis Cache must be in a running state
    
    Security Considerations:
    - This script performs destructive operations and should only be used in controlled environments
    - Ensure proper RBAC permissions are in place
    - Consider implementing approval workflows for production environments
    
    Logging:
    - All operations are logged with timestamps and severity levels
    - Logs are written to Azure Automation output streams for monitoring
#>

#Requires -Modules Az.RedisCache, Az.Accounts
#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma separated resource IDs of the Azure Redis Caches")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$false, HelpMessage="Dummy parameter, this will be ignored")]
    [ValidateNotNullOrEmpty()]
    [long]$Duration,

    [Parameter(Mandatory=$false, HelpMessage="Optional target availability zone hint (informational only).")]
    [string]$TargetZone,

    [Parameter(Mandatory=$false, HelpMessage="Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.")]
    [string]$UAMIClientId
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
            "INFO"    { Write-Verbose $logEntry }
            "WARNING" { Write-Warning $logEntry }
            "ERROR"   { Write-Error $logEntry }
            "SUCCESS" { Write-Verbose $logEntry }
        }
    }

    <#
    .SYNOPSIS
        Converts an Azure Redis Cache resource ID into its components.

    .DESCRIPTION
        This function extracts subscription ID, resource group name, and cache name
        from a properly formatted Azure Redis Cache resource ID.
        It validates the format and throws an error if the format is invalid.

    .PARAMETER ResourceId
        The Azure resource ID to parse.

    .OUTPUTS
        Returns a hashtable containing:
        - SubscriptionId: The Azure subscription ID
        - ResourceGroup: The resource group name
        - CacheName: The Redis cache name

    .EXAMPLE
        $resourceInfo = ConvertFrom-ResourceId -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.Cache/redis/mycache"
        # Returns: @{SubscriptionId="12345678-1234-1234-1234-123456789012"; ResourceGroup="myRG"; CacheName="mycache"}

    .NOTES
        Only supports Azure Redis Cache resource IDs.
    #>
    function ConvertFrom-ResourceId {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$ResourceId
        )
        
        if ($ResourceId -match "^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Cache/redis/([^/]+)$") {
            return @{
                SubscriptionId = $Matches[1]
                ResourceGroup = $Matches[2]
                CacheName = $Matches[3]
            }
        } else {
            throw "Invalid Redis Cache resource ID format. Expected format: /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Cache/redis/{cache-name}"
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
            Write-Log "Authentication successful" "SUCCESS"
        }

    .NOTES
        This function is designed specifically for Azure Automation environments.
        It requires a Managed Identity to be configured on the Automation Account.
    #>
    function Connect-ToAzure {
        [CmdletBinding()]
        [OutputType([bool])]
        param(
            [Parameter(Mandatory = $false)]
            [string]$ClientId,
            [Parameter(Mandatory = $false)]
            [string]$SubscriptionId
        )
        
        try {
            if ([string]::IsNullOrEmpty($ClientId)) {
                Write-Log "Authenticating to Azure using System-Assigned Managed Identity..." "INFO"
                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            } else {
                Write-Log "Authenticating to Azure using User-Assigned Managed Identity (ClientId: $ClientId)..." "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -ErrorAction Stop | Out-Null
            }

            # If a subscription ID is provided, set the context to that subscription immediately
            if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
                Write-Log "Setting subscription context to $SubscriptionId" "INFO"
                Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
            }
            
            $newContext = Get-AzContext -ErrorAction Stop
            Write-Log "Successfully authenticated as $($newContext.Account.Id) on subscription $($newContext.Subscription.Name)" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Azure authentication failed: $($_.Exception.Message)" "ERROR"
            throw "Azure authentication failed: $($_.Exception.Message)"
        }
    }

    <#
    .SYNOPSIS
        Validates and imports required PowerShell modules for Redis Cache operations.

    .DESCRIPTION
        This function checks for the availability of the Az.RedisCache module and imports it
        if it's available but not currently loaded. This is essential for Redis Cache
        operations in Azure Automation environments.

    .OUTPUTS
        Returns $true if the module is available and loaded, $false otherwise.

    .EXAMPLE
        if (Initialize-RequiredModules) {
            Write-Log "Modules ready" "SUCCESS"
        }

    .NOTES
        The Az.RedisCache module must be imported into the Azure Automation Account
        before this function can succeed.
    #>
    function Initialize-RequiredModules {
        [CmdletBinding()]
        [OutputType([bool])]
        param()
        
        try {
            Write-Log "Checking for required Az.RedisCache module..." "INFO"
            if (-not (Get-Module -Name "Az.RedisCache" -ListAvailable)) {
                throw "Az.RedisCache module is not available in this Automation Account"
            }
            
            if (-not (Get-Module -Name "Az.RedisCache")) {
                Write-Log "Importing Az.RedisCache module..." "INFO"
                Import-Module Az.RedisCache -ErrorAction Stop -Force
            }
            
            Write-Log "Az.RedisCache module is ready" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Failed to initialize required modules: $($_.Exception.Message)" "ERROR"
            throw "Module initialization failed: $($_.Exception.Message)"
        }
    }

    <#
    .SYNOPSIS
        Performs a forced restart of the primary node on an Azure Redis Cache.

    .DESCRIPTION
        This function executes a forced restart operation on the primary node of the specified Redis Cache.
        It handles subscription context switching if needed and provides detailed logging throughout the process.

    .PARAMETER ResourceGroupName
        The name of the resource group containing the Redis cache.

    .PARAMETER CacheName
        The name of the Redis Cache to restart.

    .PARAMETER SubscriptionId
        The Azure subscription ID. If provided and different from current context, 
        the function will switch to this subscription.

    .OUTPUTS
        Returns $true if the restart operation is successful, $false otherwise.

    .EXAMPLE
        $success = Invoke-RedisCacheRestart -ResourceGroupName "myRG" -CacheName "mycache" -SubscriptionId "12345678-1234-1234-1234-123456789012"

    .NOTES
        This operation will cause temporary unavailability of the Redis Cache.
        Use with caution, especially in production environments.
        The operation specifically targets the primary node for maximum impact.
    #>
    function Invoke-RedisCacheRestart {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param (
            [Parameter(Mandatory = $true)]
            [string]$ResourceGroupName,
            
            [Parameter(Mandatory = $true)]
            [string]$CacheName,
            
            [Parameter(Mandatory = $false)]
            [string]$SubscriptionId
        )
        
        try {
            Write-Log "Verifying Redis Cache '$CacheName' in RG '$ResourceGroupName'" "INFO"
            $redisCache = Get-AzRedisCache -ResourceGroupName $ResourceGroupName -Name $CacheName -ErrorAction Stop
            Write-Log "Found Redis Cache: $($redisCache.Name) (Status: $($redisCache.ProvisioningState))" "INFO"
            
            Write-Log "Initiating forced reboot of primary replica for Redis Cache: $CacheName" "INFO"
            $rebootResult = Reset-AzRedisCache -ResourceGroupName $ResourceGroupName -Name $CacheName -RebootType "PrimaryNode" -Force -ErrorAction Stop
            
            Write-Log "Force reboot command executed successfully on primary replica for '$CacheName'. Result: $($rebootResult.Status)" "SUCCESS"
            return [pscustomobject]@{ IsSuccess = $true; Status = 'Succeeded'; Message = "Reboot initiated successfully" }
        }
        catch {
            $errorMessage = "Failed to perform Redis Cache restart for '$CacheName': $($_.Exception.Message)"
            Write-Log $errorMessage "ERROR"
            return [pscustomobject]@{ IsSuccess = $false; Status = 'Failed'; Message = $errorMessage }
        }
    }

    #endregion Functions
}

#region Main Script Execution
# Set VerbosePreference to Continue to see Write-Verbose logs in automation job streams.
$VerbosePreference = 'Continue'

Write-Verbose "============================================================"
Write-Verbose "AZURE REDIS CACHE RESTART SCRIPT"
Write-Verbose "============================================================"
Write-Verbose "Starting Redis Cache Restart operation..."
Write-Verbose "Raw Input: $ResourceIds"
$cacheIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $cacheIds -or $cacheIds.Count -eq 0) { throw "No valid Redis cache resource IDs provided" }
Write-Verbose "Parsed $($cacheIds.Count) Redis cache id(s)."

# Initial connection check in main thread
try {
    if ($UAMIClientId) {
        Connect-AzAccount -Identity -AccountId $UAMIClientId -ErrorAction Stop | Out-Null
    } else {
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    }
    $ctx = Get-AzContext -ErrorAction Stop
    Write-Verbose "Initial connection successful as $($ctx.Account.Id) on subscription $($ctx.Subscription.Name)"
} catch {
    throw "Initial Azure authentication failed. Please check Managed Identity configuration. Error: $($_.Exception.Message)"
}

$scriptStart = Get-Date

Write-Verbose "Starting parallel processing of $($cacheIds.Count) Redis caches"

$functionsScript = $functions.ToString()

$resultsRaw = $cacheIds | ForEach-Object -Parallel {
    # Set VerbosePreference in the parallel runspace so Write-Verbose logs appear
    $VerbosePreference = 'Continue'
    
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
        # Parse resource ID first to get the subscription
        $info = ConvertFrom-ResourceId -ResourceId $rid

        # Authenticate and initialize modules in the parallel runspace, passing the target subscription
        Connect-ToAzure -ClientId $using:UAMIClientId -SubscriptionId $info.SubscriptionId | Out-Null
        Initialize-RequiredModules | Out-Null

        $faultResult = Invoke-RedisCacheRestart -ResourceGroupName $info.ResourceGroup -CacheName $info.CacheName -SubscriptionId $info.SubscriptionId
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
    GlobalError= if ($overallStatus -eq 'Failed') { 'All Redis cache restart operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some operations failed.' } else { $null }
}
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Fail the runbook if any resource could not be faulted
if ($failureCount -gt 0) {
    $errorMsg = "Runbook failed: $failureCount out of $($cacheIds.Count) Redis cache(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Verbose "All Redis cache restart operations completed successfully."

#endregion Main Script Execution