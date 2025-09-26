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

#Requires -Modules Az.PostgreSQL
#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma separated Resource IDs of the Azure PostgreSQL Flexible Servers")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$false, HelpMessage="Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.")]
    [string]$UAMIClientId,

    [Parameter(Mandatory=$false, HelpMessage="Maximum number of concurrent failover operations")]
    [ValidateRange(1,50)]
    [int]$ThrottleLimit = 5
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
        "INFO" { 
            Write-Debug $logEntry 
        }
        "WARNING" { 
            Write-Warning $logEntry 
        }
        "ERROR" { 
            Write-Error $logEntry 
        }
        "SUCCESS" { 
            Write-Debug $logEntry 
        }
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
    
    try {
        # Use regex to extract components from PostgreSQL Flexible Server resource ID
        # Expected format: /subscriptions/{guid}/resourceGroups/{name}/providers/Microsoft.DBforPostgreSQL/flexibleServers/{name}
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
    catch {
        throw "Failed to parse resource ID: $_"
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
            if ([string]::IsNullOrEmpty($ClientId)) 
            {
                Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            } 
            else 
            {
                Write-Log "Authenticating to Azure via User-Assigned Managed Identity (ClientId: $ClientId)" "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -ErrorAction Stop | Out-Null
            }
            
            Write-Log "Connect command executed" "SUCCESS"
            # Verify connection was successful
            $context = Get-AzContext -ErrorAction Stop
            Write-Log "Successfully connected to Azure using Managed Identity" "SUCCESS"
            Write-Log "Connected as: $($context.Account.Id) in subscription: $($context.Subscription.Name)" "INFO"
            return $true
    }
    catch 
    {
        Write-Log "Failed to authenticate to Azure: $($_.Exception.Message)" "ERROR"
        return $false
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
        
        # Check if the module is available
        $module = Get-Module -Name Az.PostgreSQL -ListAvailable -ErrorAction SilentlyContinue
        
        if (-not $module) {
            Write-Log "Az.PostgreSQL module is not available in this Automation Account" "ERROR"
            Write-Log "Please ensure the Az.PostgreSQL module is imported into your Azure Automation Account" "ERROR"
            return $false
        }
        
        # Check if the module is already loaded
        $loadedModule = Get-Module -Name Az.PostgreSQL -ErrorAction SilentlyContinue
        
        if (-not $loadedModule) {
            Write-Log "Az.PostgreSQL module found but not loaded. Importing module..." "INFO"
            Import-Module Az.PostgreSQL -ErrorAction Stop -Force
            Write-Log "Az.PostgreSQL module imported successfully" "SUCCESS"
        }
        else {
            Write-Log "Az.PostgreSQL module is already loaded (Version: $($loadedModule.Version))" "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to initialize required modules: $($_.Exception.Message)" "ERROR"
        return $false
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
    [OutputType([bool])]
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
    
    try 
    {
        Write-Log "Initiating unplanned restart with failover for server '$ServerName' in resource group '$ResourceGroupName'..." "INFO"
        
        # Execute the forced failover restart
        # This operation will:
        # 1. Force an immediate failover to a standby replica (if available)
        # 2. Restart the PostgreSQL service
        # 3. May result in brief downtime during the transition
        $restartResult = Restart-AzPostgreSqlFlexibleServer `
            -ResourceGroupName $ResourceGroupName `
            -Name $ServerName `
            -RestartWithFailover `
            -FailoverMode ForcedFailover `
            -ErrorAction Stop
            
        Write-Log "Successfully initiated failover for server '$ServerName'" "SUCCESS"
        Write-Log "Restart operation details: $($restartResult | ConvertTo-Json -Depth 2 -Compress)" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to restart server '$ServerName' with failover: $($_.Exception.Message)" "ERROR"
        Write-Log "Full error details: $($_ | Out-String)" "ERROR"
        return $false    }
}

#endregion Functions

#region Main Script Execution

<#
    MAIN SCRIPT EXECUTION SECTION
    
    This section contains the primary script logic that orchestrates the PostgreSQL
    server failover process. It follows these main steps:
    
    1. Initialize script execution with logging
    2. Authenticate to Azure using Managed Identity
    3. Parse the provided resource IDs to extract server details
    4. Validate and import required PowerShell modules
    5. Execute the failover restart operation for each server
    6. Provide aggregated operation results in JSON format
    
    All operations include comprehensive error handling and logging for Azure
    Automation monitoring and troubleshooting purposes.
#>

# Script execution banner and initial setup
Write-Log "============================================================" "INFO"
Write-Log "AZURE POSTGRESQL FLEXIBLE SERVER FAILOVER SCRIPT" "INFO"
Write-Log "Version: 2.2 (PS7 Always-Parallel) | Date: 2025-09-25" "INFO"
Write-Log "============================================================" "INFO"
Write-Log "Starting PostgreSQL Flexible Server Failover operation..." "INFO"
Write-Log "Raw Input: $ResourceIds" "INFO"

$pgIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $pgIds -or $pgIds.Count -eq 0) { throw "No valid PostgreSQL resource IDs provided" }
Write-Log "Parsed $($pgIds.Count) PostgreSQL server id(s)." 'INFO'

$scriptStart = Get-Date
$opResults = @()

try {
    Write-Log "Authenticating to Azure..." 'INFO'
    if (-not (Connect-ToAzure -ClientId $UAMIClientId)) { throw "Authentication failed" }
    if (-not (Initialize-RequiredModules)) { throw "Required modules not available" }

    Write-Log "Executing always-parallel mode. ThrottleLimit=$ThrottleLimit" 'INFO'
    # Capture needed functions/variables for parallel scriptblocks
    $functionDefs = @(
        (Get-Command Write-Log).ScriptBlock.ToString(),
        (Get-Command ConvertFrom-ResourceId).ScriptBlock.ToString(),
        (Get-Command Restart-PostgreSQLServerWithFailover).ScriptBlock.ToString(),
        (Get-Command Connect-ToAzure).ScriptBlock.ToString(),
        (Get-Command Initialize-RequiredModules).ScriptBlock.ToString()
    ) -join "`n`n"

    $opResults = $pgIds | ForEach-Object -Parallel {
        param($rid, $uami, $funcs)
        Invoke-Expression $funcs
        $start = Get-Date
        $result = [pscustomobject]@{ ResourceId=$rid; IsSuccess=$false; ErrorMessage=$null; StartTime=$start; EndTime=$start; Status='FailedToStart' }
        try {
            if (-not (Connect-ToAzure -ClientId $uami)) { throw "Auth failed in parallel runspace" }
            if (-not (Initialize-RequiredModules)) { throw "Module init failed in parallel runspace" }
            $info = ConvertFrom-ResourceId -ResourceId $rid
            if ($info.SubscriptionId) { Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null }
            $ok = Restart-PostgreSQLServerWithFailover -ResourceGroupName $info.ResourceGroup -ServerName $info.ServerName -SubscriptionId $info.SubscriptionId
            $end = Get-Date
            $result.IsSuccess = $ok
            $result.ErrorMessage = if ($ok) { $null } else { 'Failover restart failed' }
            $result.EndTime = $end
            $result.Status = if ($ok) { 'Succeeded' } else { 'Failed' }
        }
        catch {
            $result.EndTime = Get-Date
            $result.ErrorMessage = $_.Exception.Message
            $result.Status = 'Failed'
        }
        return $result
    } -ThrottleLimit $ThrottleLimit -ArgumentList $UAMIClientId, $functionDefs
}
catch { Write-Log "Critical top-level error: $($_.Exception.Message)" 'ERROR' }

$scriptEnd = Get-Date
$successCount = ($opResults | Where-Object { $_.IsSuccess }).Count
$failureCount = ($opResults | Where-Object { -not $_.IsSuccess }).Count
$overallStatus = if ($failureCount -eq 0) { 'Success' } elseif ($successCount -gt 0) { 'PartialSuccess' } else { 'Failed' }

$resourceResults = @()
foreach ($r in $opResults) {
    $durationMs = [int]([Math]::Round((($r.EndTime) - $r.StartTime).TotalMilliseconds))
    $err = $null
    if (-not $r.IsSuccess) { $err = @{ ErrorCode='FailedToFaultResource'; Message=$r.ErrorMessage; Details=$r.ErrorMessage; Category=$r.Status; IsRetryable=$false } }
    $resourceResults += @{ ResourceId=$r.ResourceId; IsSuccess=$r.IsSuccess; Error=$err; ProcessedAt=$r.EndTime.ToUniversalTime(); ProcessingDurationMs=$durationMs; Metadata=@{ Status=$r.Status } }
}
$executionResult = [ordered]@{ Status=$overallStatus; ResourceResults=$resourceResults; SuccessCount=$successCount; FailureCount=$failureCount; ExecutionStartTime=$scriptStart.ToUniversalTime(); ExecutionEndTime=$scriptEnd.ToUniversalTime(); GlobalError= if ($overallStatus -eq 'Failed') { 'All PostgreSQL failover operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some failover operations failed.' } else { $null } }
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson
# Write-Log "Overall Status: $overallStatus (Success=$successCount Failure=$failureCount)" 'INFO'
# Write-Log "Script execution completed" 'INFO'

#endregion Main Script Execution