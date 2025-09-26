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

#Requires -Modules Az.RedisCache

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma separated resource IDs of the Azure Redis Caches")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$false, HelpMessage="Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.")]
    [string]$UAMIClientId
)

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
    
    # Create timestamp for log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to appropriate Azure Runbook output stream based on severity level
    switch ($Level) {
        "INFO"    { Write-Information $logEntry -InformationAction Continue }
        "WARNING" { Write-Warning $logEntry }
        "ERROR"   { Write-Error $logEntry }
        "SUCCESS" { Write-Information $logEntry -InformationAction Continue }
        default   { Write-Information $logEntry -InformationAction Continue }
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
    
    try {
        Write-Log "Parsing resource ID: $ResourceId" "INFO"
        
        # Parse Redis Cache resource ID format
        if ($ResourceId -match "^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Cache/redis/([^/]+)$") {
            $result = @{
                SubscriptionId = $Matches[1]
                ResourceGroup = $Matches[2]
                CacheName = $Matches[3]
            }
            
            Write-Log "Successfully parsed resource ID - Subscription: $($result.SubscriptionId), RG: $($result.ResourceGroup), Cache: $($result.CacheName)" "SUCCESS"
            return $result
        } else {
            throw "Invalid Redis Cache resource ID format. Expected format: /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Cache/redis/{cache-name}"
        }
    }
    catch {
        Write-Log "Failed to parse resource ID: $($_.Exception.Message)" "ERROR"
        throw
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
        [string]$ClientId
    )
    
    try 
    {
        # Check if already connected to Azure
        $currentContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($currentContext) {
            Write-Log "Already authenticated to Azure as $($currentContext.Account.Id)" "INFO"
            return $true
        }
        
        # Connect using Managed Identity
        if ([string]::IsNullOrEmpty($ClientId)) {
            Write-Log "Authenticating to Azure using System-Assigned Managed Identity..." "INFO"
            $connectResult = Connect-AzAccount -Identity -ErrorAction Stop
        } else {
            Write-Log "Authenticating to Azure using User-Assigned Managed Identity (ClientId: $ClientId)..." "INFO"
            $connectResult = Connect-AzAccount -Identity -AccountId $ClientId -ErrorAction Stop
        }
        
        $newContext = Get-AzContext -ErrorAction Stop
        Write-Log "Successfully authenticated as $($newContext.Account.Id) on subscription $($newContext.Subscription.Name)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Azure authentication failed: $($_.Exception.Message)" "ERROR"
        return $false
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
        Write-Log "Checking for required PowerShell modules..." "INFO"
        
        # Check if Az.RedisCache module is available
        $redisCacheModule = Get-Module -Name "Az.RedisCache" -ListAvailable -ErrorAction SilentlyContinue
        if (-not $redisCacheModule) {
            Write-Log "Az.RedisCache module is not available in this Automation Account" "ERROR"
            Write-Log "Please import the Az.RedisCache module into the Azure Automation Account" "ERROR"
            return $false
        }
        
        # Import the module if it's not already loaded
        $loadedModule = Get-Module -Name "Az.RedisCache" -ErrorAction SilentlyContinue
        if (-not $loadedModule) {
            Write-Log "Importing Az.RedisCache module..." "INFO"
            Import-Module Az.RedisCache -ErrorAction Stop -Force
            Write-Log "Az.RedisCache module imported successfully" "SUCCESS"
        } else {
            Write-Log "Az.RedisCache module is already loaded" "INFO"
        }
        
        # Verify module functions are available
        $rebootCommand = Get-Command -Name "Reset-AzRedisCache" -ErrorAction SilentlyContinue
        if (-not $rebootCommand) {
            Write-Log "Reset-AzRedisCache command not found in Az.RedisCache module" "ERROR"
            return $false
        }
        
        Write-Log "All required modules are loaded and ready" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to initialize required modules: $($_.Exception.Message)" "ERROR"
        return $false
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
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$CacheName,
        
        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId
    )
    
    try 
    {
        # Switch subscription context if needed
        if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
            $currentContext = Get-AzContext
            if ($currentContext.Subscription.Id -ne $SubscriptionId) {
                Write-Log "Switching to subscription: $SubscriptionId" "INFO"
                Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
                Write-Log "Successfully switched to subscription: $SubscriptionId" "SUCCESS"
            } else {
                Write-Log "Already in the correct subscription context" "INFO"
            }
        }
        
        # Verify Redis Cache exists and get its current state
        Write-Log "Verifying Redis Cache exists: $CacheName in resource group: $ResourceGroupName" "INFO"
        $redisCache = Get-AzRedisCache -ResourceGroupName $ResourceGroupName -Name $CacheName -ErrorAction Stop
        Write-Log "Found Redis Cache: $($redisCache.Name) (Status: $($redisCache.ProvisioningState), Sku: $($redisCache.Sku.Name))" "INFO"
        
        # Perform forced reboot on primary replica
        Write-Log "Initiating forced reboot of primary replica for Redis Cache: $CacheName" "INFO"
        
        $rebootResult = Reset-AzRedisCache -ResourceGroupName $ResourceGroupName -Name $CacheName -RebootType "PrimaryNode" -Force -PassThru -ErrorAction Stop
        
        Write-Log "Force reboot command executed successfully on primary replica" "SUCCESS"
        Write-Log "Restart operation initiated - the cache may take several minutes to become available again" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to perform Redis Cache restart: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion Functions

#region Main Script Execution

<#
    MAIN SCRIPT EXECUTION SECTION
    
    This section contains the primary script logic that orchestrates the Redis Cache
    restart process. It follows these main steps:
    
    1. Initialize script execution with logging
    2. Authenticate to Azure using Managed Identity
    3. Parse the provided resource ID to extract cache details
    4. Validate and import required PowerShell modules
    5. Execute the restart operation on the primary node
    6. Provide operation summary and results
    
    All operations include comprehensive error handling and logging for Azure
    Automation monitoring and troubleshooting purposes.
#>

# Script execution banner and initial setup
Write-Log "============================================================" "INFO"
Write-Log "AZURE REDIS CACHE RESTART SCRIPT" "INFO"
Write-Log "Version: 1.3 | Date: 2025-09-19" "INFO"
Write-Log "============================================================" "INFO"
Write-Log "Starting Redis Cache Restart operation..." "INFO"
Write-Log "Raw Input: $ResourceIds" "INFO"
$cacheIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $cacheIds -or $cacheIds.Count -eq 0) { throw "No valid Redis cache resource IDs provided" }
Write-Log "Parsed $($cacheIds.Count) Redis cache id(s)." 'INFO'

if (-not (Connect-ToAzure -ClientId $UAMIClientId)) { throw "Authentication failed" }
if (-not (Initialize-RequiredModules)) { throw "Module init failed" }

$scriptStart = Get-Date

# Capture function definitions for parallel execution
$functionDefs = @"
$(Get-Content Function:\Write-Log -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\ConvertFrom-ResourceId -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Connect-ToAzure -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Initialize-RequiredModules -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Invoke-RedisCacheRestart -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })
"@

$results = $cacheIds | ForEach-Object -Parallel {
    # Re-create function definitions in parallel runspace
    Invoke-Expression $using:functionDefs
    
    $rid = $_
    Write-Log "Processing Redis Cache: $rid" 'INFO'
    $parseErr = $null
    $info = $null
    $start = Get-Date
    try { $info = ConvertFrom-ResourceId -ResourceId $rid } catch { $parseErr = $_.Exception.Message }
    if ($parseErr) {
        return [pscustomobject]@{ ResourceId=$rid; IsSuccess=$false; ErrorMessage=$parseErr; StartTime=$start; EndTime=$start; Status='FailedToStart' }
    }
    try {
        # Re-authenticate within parallel runspace
        if (-not (Connect-ToAzure -ClientId $using:UAMIClientId)) { 
            throw "Authentication failed in parallel runspace" 
        }
        if (-not (Initialize-RequiredModules)) { 
            throw "Module initialization failed in parallel runspace" 
        }
        
        $success = Invoke-RedisCacheRestart -ResourceGroupName $info.ResourceGroup -CacheName $info.CacheName -SubscriptionId $info.SubscriptionId
        $end = Get-Date
        return [pscustomobject]@{ ResourceId=$rid; IsSuccess=$success; ErrorMessage= if ($success) { $null } else { 'Redis cache restart failed' }; StartTime=$start; EndTime=$end; Status= (if ($success) { 'Succeeded' } else { 'Failed' }) }
    } catch { 
        $end = Get-Date
        return [pscustomobject]@{ ResourceId=$rid; IsSuccess=$false; ErrorMessage=$_.Exception.Message; StartTime=$start; EndTime=$end; Status='Failed' } 
    }
} -ThrottleLimit ([System.Environment]::ProcessorCount)

$scriptEnd = Get-Date
$successCount = ($results | Where-Object { $_.IsSuccess }).Count
$failureCount = ($results | Where-Object { -not $_.IsSuccess }).Count
$overallStatus = if ($failureCount -eq 0) { 'Success' } elseif ($successCount -gt 0) { 'PartialSuccess' } else { 'Failed' }

$resourceResults = @()
foreach ($r in $results) {
    $durationMs = [int]([Math]::Round((($r.EndTime) - $r.StartTime).TotalMilliseconds))
    $err = $null
    if (-not $r.IsSuccess) { $err = @{ ErrorCode='FailedToFaultResource'; Message=$r.ErrorMessage; Details=$r.ErrorMessage; Category=$r.Status; IsRetryable=$false } }
    $resourceResults += @{ ResourceId=$r.ResourceId; IsSuccess=$r.IsSuccess; Error=$err; ProcessedAt=$r.EndTime.ToUniversalTime(); ProcessingDurationMs=$durationMs; Metadata=@{ Status=$r.Status } }
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

# Write-Log "Script execution completed" "INFO"

#endregion Main Script Execution