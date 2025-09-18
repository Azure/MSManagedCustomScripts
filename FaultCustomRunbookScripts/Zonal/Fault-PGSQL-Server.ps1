<#
.SYNOPSIS
    Performs unplanned restart with failover for an Azure PostgreSQL Flexible Server in an Azure Runbook.

.DESCRIPTION
    This Azure Runbook script triggers an unplanned restart with failover for an Azure PostgreSQL Flexible Server.
    It accepts a resource ID as input and performs forced failover operation on the server.
    The script includes detailed logging and error handling optimized for Azure Automation.
    
    This script is designed to simulate planned/unplanned outages for resilience testing purposes.
    It performs the following operations:
    1. Authenticates to Azure using Managed Identity
    2. Validates and imports required PowerShell modules
    3. Parses the provided PostgreSQL server resource ID
    4. Executes a forced failover restart on the target server
    5. Provides comprehensive logging throughout the process

.PARAMETER ResourceId
    The resource ID for the Azure PostgreSQL Flexible Server to be restarted with failover.
    The resource ID should be in the format:
    "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.DBforPostgreSQL/flexibleServers/{server-name}"

.EXAMPLE
    # Example 1: Direct execution with resource ID
    .\Fault-PGSQL-Server.ps1 -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.DBforPostgreSQL/flexibleServers/myserver1"
    
.NOTES
    Author: Azure DevOps Team
    Date: 2025-05-26
    Version: 1.3
    
    Prerequisites:
    - Az.PostgreSQL module must be imported in the Azure Automation account
    - Runbook must run with appropriate permissions (Contributor role on target PostgreSQL servers)
    - Managed Identity or Run As Account must be configured for the Automation Account
    - Target PostgreSQL server must be a Flexible Server (not Single Server)
    
    Security Considerations:
    - This script performs destructive operations and should only be used in controlled environments
    - Ensure proper RBAC permissions are in place
    - Consider implementing approval workflows for production environments
    
    Logging:
    - All operations are logged with timestamps and severity levels
    - Logs are written to Azure Automation output streams for monitoring
#>

#Requires -Modules Az.PostgreSQL

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Resource ID of the Azure PostgreSQL Flexible Server")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceId,

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
        "INFO" { 
            Write-Output $logEntry 
        }
        "WARNING" { 
            Write-Warning $logEntry 
        }
        "ERROR" { 
            Write-Error $logEntry 
        }
        "SUCCESS" { 
            Write-Output $logEntry 
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
    3. Parse the provided resource ID to extract server details
    4. Validate and import required PowerShell modules
    5. Execute the failover restart operation
    6. Provide operation summary and results
    
    All operations include comprehensive error handling and logging for Azure
    Automation monitoring and troubleshooting purposes.
#>

# Script execution banner and initial setup
Write-Log "============================================================" "INFO"
Write-Log "AZURE POSTGRESQL FLEXIBLE SERVER FAILOVER SCRIPT" "INFO"
Write-Log "Version: 1.3 | Date: 2025-05-26" "INFO"
Write-Log "============================================================" "INFO"
Write-Log "Starting PostgreSQL Flexible Server Failover operation..." "INFO"
Write-Log "Target Resource: $ResourceId" "INFO"

# Initialize success tracking variable
$operationSuccess = $false
$startTime = Get-Date

try {
    # Step 1: Authenticate to Azure
    Write-Log "Step 1: Authenticating to Azure..." "INFO"

    Write-Log "Authenticating with Azure using Runbook Identity" "INFO"
    
    # Step 2: Authenticate to Azure using Managed Identity
    if (-not (Connect-ToAzure -ClientId $UAMIClientId)) { throw "Authentication failed" }
    
    Write-Log "Connect command executed" "SUCCESS"

    # Step 3: Parse and validate resource ID
    Write-Log "Step 3: Parsing PostgreSQL server resource ID..." "INFO"
    $resourceInfo = ConvertFrom-ResourceId -ResourceId $ResourceId
    
    Write-Log "Extracted resource information:" "INFO"
    Write-Log "  - Subscription ID: $($resourceInfo.SubscriptionId)" "INFO"
    Write-Log "  - Resource Group: $($resourceInfo.ResourceGroup)" "INFO"
    Write-Log "  - Server Name: $($resourceInfo.ServerName)" "INFO"

    # Switch subscription context
    if ($resourceInfo.SubscriptionId) 
    {
        Set-AzContext -SubscriptionId $resourceInfo.SubscriptionId -ErrorAction Stop | Out-Null
        Write-Log "Switched to subscription $($resourceInfo.SubscriptionId)" "INFO"
    }

    # Verify connection was successful
    $context = Get-AzContext -ErrorAction Stop
    Write-Log "Successfully connected to Azure using Managed Identity" "SUCCESS"
    Write-Log "Connected as: $($context.Account.Id) in subscription: $($context.Subscription.Name)" "INFO"

    if (-not ($context)) {
        throw "Azure authentication failed. Cannot proceed with failover operation."
    }
    
    # Step 4: Initialize required modules
    Write-Log "Step 2: Validating required PowerShell modules..." "INFO"
    if (-not (Initialize-RequiredModules)) {
        throw "Required modules are not available. Cannot proceed with failover operation."
    }

    # Step 5: Execute failover restart operation
    Write-Log "Step 4: Executing PostgreSQL server failover restart..." "INFO"
    $operationSuccess = Restart-PostgreSQLServerWithFailover `
        -ResourceGroupName $resourceInfo.ResourceGroup `
        -ServerName $resourceInfo.ServerName `
        -SubscriptionId $resourceInfo.SubscriptionId
    
    if ($operationSuccess) {
        Write-Log "PostgreSQL server failover completed successfully" "SUCCESS"
    }
    else {
        throw "PostgreSQL server failover operation failed"
    }
}
catch {
    Write-Log "Critical error during script execution: $($_.Exception.Message)" "ERROR"
    Write-Log "Full error details: $($_ | Out-String)" "ERROR"
    $operationSuccess = $false
}

# Step 6: Operation summary and cleanup
$endTime = Get-Date
$executionDuration = $endTime - $startTime

Write-Log "============================================================" "INFO"
Write-Log "OPERATION SUMMARY" "INFO"
Write-Log "============================================================" "INFO"
Write-Log "Resource ID: $ResourceId" "INFO"
Write-Log "Start Time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" "INFO"
Write-Log "End Time: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" "INFO"
Write-Log "Execution Duration: $($executionDuration.ToString('hh\:mm\:ss'))" "INFO"
Write-Log "Operation Result: $(if ($operationSuccess) { 'SUCCESS' } else { 'FAILED' })" $(if ($operationSuccess) { "SUCCESS" } else { "ERROR" })

if ($operationSuccess) {
    Write-Log "PostgreSQL Flexible Server failover operation completed successfully" "SUCCESS"
    Write-Log "The server should now be available after the failover process" "INFO"
}
else {
    Write-Log "PostgreSQL Flexible Server failover operation failed" "ERROR"
    Write-Log "Please check the error logs above for detailed failure information" "ERROR"
    
    # Throw an exception to ensure the Azure Runbook reports failure
    throw "Failover operation failed for PostgreSQL server: $ResourceId"
}

Write-Log "Script execution completed" "INFO"

#endregion Main Script Execution