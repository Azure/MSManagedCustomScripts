<#
.SYNOPSIS
    Performs unplanned failover for an Azure MySQL Flexible Server in an Azure Runbook.

.DESCRIPTION
    This Azure Runbook script triggers an unplanned failover for an Azure MySQL Flexible Server.
    It accepts a resource ID as input and performs forced failover operation on the server.
    The script includes detailed logging and error handling optimized for Azure Automation.
    
    This script is designed to simulate planned/unplanned outages for resilience testing purposes.
    It performs the following operations:
    1. Authenticates to Azure using Managed Identity
    2. Validates and imports required PowerShell modules
    3. Parses the provided MySQL server resource ID
    4. Executes a forced failover on the target server using REST API
    5. Provides comprehensive logging throughout the process

.PARAMETER ResourceId
    The resource ID for the Azure MySQL Flexible Server to be failed over.
    The resource ID should be in the format:
    "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.DBforMySQL/flexibleServers/{server-name}"

.EXAMPLE
    # Example 1: Direct execution with resource ID
    .\Fault-MYSQL-Server.ps1 -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.DBforMySQL/flexibleServers/myserver1"
    
.NOTES
    Author: Azure DevOps Team
    Date: 2025-05-26
    Version: 1.0
    
    Prerequisites:
    - Az.Accounts module must be imported in the Azure Automation account
    - Runbook must run with appropriate permissions (Contributor role on target MySQL servers)
    - Managed Identity or Run As Account must be configured for the Automation Account
    - Target MySQL server must be a Flexible Server (not Single Server)
    
    Security Considerations:
    - This script performs destructive operations and should only be used in controlled environments
    - Ensure proper RBAC permissions are in place
    - Consider implementing approval workflows for production environments
    
    Logging:
    - All operations are logged with timestamps and severity levels
    - Logs are written to Azure Automation output streams for monitoring
#>

#Requires -Modules Az.Accounts

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma separated resource IDs of the Azure MySQL Flexible Servers")]
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
        "INFO" { 
            Write-Information $logEntry -InformationAction Continue
        }
        "WARNING" { 
            Write-Warning $logEntry 
        }
        "ERROR" { 
            Write-Error $logEntry 
        }
        "SUCCESS" { 
            Write-Information $logEntry -InformationAction Continue
        }
    }
}

<#
.SYNOPSIS
    Converts an Azure MySQL Flexible Server resource ID into its components.

.DESCRIPTION
    This function extracts subscription ID, resource group name, and server name
    from a properly formatted Azure MySQL Flexible Server resource ID.
    It validates the format and throws an error if the format is invalid.

.PARAMETER ResourceId
    The Azure resource ID to parse.

.OUTPUTS
    Returns a hashtable containing:
    - SubscriptionId: The Azure subscription ID
    - ResourceGroup: The resource group name
    - ServerName: The MySQL server name

.EXAMPLE
    $resourceInfo = ConvertFrom-ResourceId -ResourceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.DBforMySQL/flexibleServers/myserver"
    # Returns: @{SubscriptionId="12345678-1234-1234-1234-123456789012"; ResourceGroup="myRG"; ServerName="myserver"}

.NOTES
    Only supports Azure MySQL Flexible Server resource IDs.
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
        # Use regex to extract components from MySQL Flexible Server resource ID
        # Expected format: /subscriptions/{guid}/resourceGroups/{name}/providers/Microsoft.DBforMySQL/flexibleServers/{name}
        if ($ResourceId -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.DBforMySQL/flexibleServers/([^/]+)") {
            return @{
                SubscriptionId = $Matches[1]
                ResourceGroup = $Matches[2]
                ServerName = $Matches[3]
            }
        }
        else {
            throw "Invalid resource ID format. Expected format: /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.DBforMySQL/flexibleServers/{server-name}"
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
        if ([string]::IsNullOrEmpty($ClientId)) {
            Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        } 
        else {
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
    catch {
        Write-Log "Failed to authenticate to Azure: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Validates and imports required PowerShell modules for MySQL operations.

.DESCRIPTION
    This function checks for the availability of the Az.Profile module and imports it
    if it's available but not currently loaded. This is essential for Azure authentication
    and REST API operations in Azure Automation environments.

.OUTPUTS
    Returns $true if the module is available and loaded, $false otherwise.

.EXAMPLE
    if (Initialize-RequiredModules) {
        Write-Log "All required modules are available"
    }

.NOTES
    The Az.Profile module must be imported into the Azure Automation Account
    before this function can succeed.
#>
function Initialize-RequiredModules {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        Write-Log "Checking for required Az.Accounts module..." "INFO"
        
        # Check if the module is available
        $module = Get-Module -Name Az.Accounts -ListAvailable -ErrorAction SilentlyContinue
        
        if (-not $module) {
            Write-Log "Az.Accounts module is not available in this Automation Account" "ERROR"
            Write-Log "Please ensure the Az.Accounts module is imported into your Azure Automation Account" "ERROR"
            return $false
        }
        
        # Check if the module is already loaded
        $loadedModule = Get-Module -Name Az.Accounts -ErrorAction SilentlyContinue
        
        if (-not $loadedModule) {
            Write-Log "Az.Accounts module found but not loaded. Importing module..." "INFO"
            Import-Module Az.Accounts -ErrorAction Stop -Force
            Write-Log "Az.Accounts module imported successfully" "SUCCESS"
        }
        else {
            Write-Log "Az.Accounts module is already loaded (Version: $($loadedModule.Version))" "INFO"
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
    Waits for an Azure async operation to complete and returns the final result.

.DESCRIPTION
    This function polls the Azure async operation status endpoint until the operation
    completes (either successfully or with failure). It implements exponential backoff
    for polling intervals and has a maximum timeout to prevent infinite waiting.

.PARAMETER AsyncOperationUrl
    The Azure-AsyncOperation URL returned from the initial REST API call.

.PARAMETER Headers
    The HTTP headers to use for the polling requests (including authorization).

.PARAMETER MaxWaitTimeMinutes
    Maximum time to wait for the operation to complete (default: 30 minutes).

.PARAMETER InitialDelaySeconds
    Initial delay between polling attempts (default: 30 seconds).

.OUTPUTS
    Returns $true if the operation completed successfully, $false if it failed or timed out.

.EXAMPLE
    $success = Wait-ForAsyncOperation -AsyncOperationUrl $url -Headers $headers

.NOTES
    Uses exponential backoff for polling intervals to reduce API load.
    Times out after MaxWaitTimeMinutes to prevent runaway polling.
#>
function Wait-ForAsyncOperation {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AsyncOperationUrl,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxWaitTimeMinutes = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$InitialDelaySeconds = 30
    )
    
    try {
        $startTime = Get-Date
        $maxWaitTime = $startTime.AddMinutes($MaxWaitTimeMinutes)
        $delaySeconds = $InitialDelaySeconds
        $maxDelaySeconds = 300 # Cap at 5 minutes
        
        Write-Log "Starting async operation polling. Max wait time: $MaxWaitTimeMinutes minutes" "INFO"
        
        do {
            Start-Sleep -Seconds $delaySeconds
            
            Write-Log "Polling async operation status..." "INFO"
            $statusResponse = Invoke-WebRequest -Uri $AsyncOperationUrl -Method GET -Headers $Headers -UseBasicParsing -ErrorAction Stop
            
            if ($statusResponse.StatusCode -eq 200 -and $statusResponse.Content) {
                $statusObj = $statusResponse.Content | ConvertFrom-Json -ErrorAction Stop
                $status = $statusObj.status
                
                Write-Log "Operation status: $status" "INFO"
                
                switch ($status.ToLower()) {
                    "succeeded" {
                        Write-Log "Async operation completed successfully" "SUCCESS"
                        return $true
                    }
                    "failed" {
                        Write-Log "Async operation failed" "ERROR"
                        if ($statusObj.error) {
                            Write-Log "Operation error details: $($statusObj.error | ConvertTo-Json -Depth 2 -Compress)" "ERROR"
                        }
                        return $false
                    }
                    "canceled" {
                        Write-Log "Async operation was canceled" "ERROR"
                        return $false
                    }
                    "inprogress" {
                        Write-Log "Operation still in progress. Continuing to poll..." "INFO"
                        # Continue polling
                    }
                    "running" {
                        Write-Log "Operation still running. Continuing to poll..." "INFO"
                        # Continue polling
                    }
                    default {
                        Write-Log "Unknown operation status: $status. Continuing to poll..." "WARNING"
                        # Continue polling for unknown statuses
                    }
                }
            }
            else {
                Write-Log "Unexpected response from async operation endpoint. Status: $($statusResponse.StatusCode)" "WARNING"
            }
            
            # Implement exponential backoff (double the delay, up to max)
            $delaySeconds = [Math]::Min($delaySeconds * 2, $maxDelaySeconds)
            
        } while ((Get-Date) -lt $maxWaitTime)
        
        # Timed out
        Write-Log "Async operation polling timed out after $MaxWaitTimeMinutes minutes" "ERROR"
        Write-Log "Last known status was: $status" "ERROR"
        return $false
    }
    catch {
        Write-Log "Error while polling async operation: $($_.Exception.Message)" "ERROR"
        Write-Log "Full error details: $($_ | Out-String)" "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Performs an unplanned failover on an Azure MySQL Flexible Server using REST API.

.DESCRIPTION
    This function executes a forced failover operation on the specified MySQL
    Flexible Server using the Azure REST API. It handles subscription context 
    switching if needed and provides detailed logging throughout the process.

.PARAMETER ResourceGroupName
    The name of the resource group containing the MySQL server.

.PARAMETER ServerName
    The name of the MySQL Flexible Server to failover.

.PARAMETER SubscriptionId
    The Azure subscription ID. If provided and different from current context, 
    the function will switch to this subscription.

.OUTPUTS
    Returns $true if the failover operation is successful, $false otherwise.

.EXAMPLE
    $success = Invoke-MySQLServerFailover -ResourceGroupName "myRG" -ServerName "myserver" -SubscriptionId "12345678-1234-1234-1234-123456789012"

.NOTES
    This operation will cause temporary unavailability of the MySQL server.
    Use with caution, especially in production environments.
    Uses the Azure REST API for MySQL Flexible Server failover operation.
#>
function Invoke-MySQLServerFailover {
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
    
    try {
        Write-Log "Initiating unplanned failover for MySQL server '$ServerName' in resource group '$ResourceGroupName'..." "INFO"
        
        # Get the current Azure context to obtain access token
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context) {
            throw "No Azure context available. Please authenticate first."
        }
        
        # Get access token for REST API calls using modern approach
        $accessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
        
        # Handle both SecureString (newer versions) and String (older versions) token formats
        if ($accessToken.Token -is [System.Security.SecureString]) {
            # Convert SecureString to plain text for REST API use
            Write-Log "Converting SecureString token to plain text for REST API use" "INFO"
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessToken.Token)
            try {
                $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            }
            finally {
                # Always clear the BSTR from memory for security
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        } else {
            # Token is already a string (common in older Az.Accounts versions or PS 5.1)
            Write-Log "Using plain text token from Get-AzAccessToken" "INFO"
            $token = $accessToken.Token
        }
        
        # Construct the REST API endpoint
        $apiVersion = "2023-12-30"
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DBforMySQL/flexibleServers/$ServerName/failover?api-version=$apiVersion"
        
        Write-Log "Calling MySQL failover REST API endpoint: $uri" "INFO"
        
        # Prepare headers for REST API call
        $headers = @{
            'Authorization' = "Bearer $token"
            'Content-Type' = 'application/json'
        }
        
        # Execute the failover REST API call
        # This is a POST request with no body required
        $response = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -UseBasicParsing -ErrorAction Stop
        
        Write-Log "API Response Status Code: $($response.StatusCode)" "INFO"
        
        # Check the HTTP status code to determine operation result
        if ($response.StatusCode -eq 200) {
            Write-Log "Successfully completed failover for MySQL server '$ServerName' (HTTP 200)" "SUCCESS"
            Write-Log "Failover operation response: $($response.Content)" "INFO"
            return $true
        }
        elseif ($response.StatusCode -eq 202) {
            Write-Log "Successfully initiated failover for MySQL server '$ServerName' (HTTP 202 - Accepted)" "INFO"
            Write-Log "Long-running operation started. Tracking operation to completion..." "INFO"
            
            # Get async operation tracking URLs
            $asyncOperationUrl = $response.Headers['Azure-AsyncOperation']
            $locationUrl = $response.Headers['Location']
            
            if ($asyncOperationUrl) {
                Write-Log "Azure-AsyncOperation URL: $asyncOperationUrl" "INFO"
                
                # Poll the async operation status until completion
                $operationResult = Wait-ForAsyncOperation -AsyncOperationUrl $asyncOperationUrl -Headers $headers
                
                if ($operationResult) {
                    Write-Log "Failover operation completed successfully" "SUCCESS"
                    return $true
                } else {
                    Write-Log "Failover operation failed during execution" "ERROR"
                    return $false
                }
            }
            elseif ($locationUrl) {
                Write-Log "Location URL: $locationUrl" "INFO"
                Write-Log "Note: Only Location header available. Operation initiated successfully but final status not tracked." "WARNING"
                return $true
            }
            else {
                Write-Log "No tracking URLs provided. Operation initiated but cannot track completion." "WARNING"
                Write-Log "Failover operation response: $($response.Content)" "INFO"
                return $true
            }
        }
        else {
            Write-Log "Unexpected status code $($response.StatusCode) from failover API" "WARNING"
            Write-Log "Response content: $($response.Content)" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to failover MySQL server '$ServerName': $($_.Exception.Message)" "ERROR"
        
        # Handle HTTP response errors with PowerShell 5.1 compatibility
        if ($_.Exception -and $_.Exception.Response) {
            try {
                $statusCode = $_.Exception.Response.StatusCode
                Write-Log "HTTP Status Code: $statusCode" "ERROR"
                
                # Try to get response content - different methods for different PS versions
                $responseContent = $null
                if ($_.Exception.Response.Content) {
                    $responseContent = $_.Exception.Response.Content
                } elseif ($_.Exception.Response.GetResponseStream) {
                    $responseStream = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($responseStream)
                    $responseContent = $reader.ReadToEnd()
                    $reader.Close()
                    $responseStream.Close()
                }
                
                if ($responseContent) {
                    try {
                        $errorObj = $responseContent | ConvertFrom-Json -ErrorAction Stop
                        Write-Log "API Error Response: $($errorObj | ConvertTo-Json -Depth 3 -Compress)" "ERROR"
                    }
                    catch {
                        Write-Log "Raw API Error Response: $responseContent" "ERROR"
                    }
                }
            }
            catch {
                Write-Log "Could not extract detailed error information from HTTP response" "ERROR"
            }
        }
        
        Write-Log "Full error details: $($_ | Out-String)" "ERROR"
        return $false
    }
}

#endregion Functions

#region Main Script Execution

<#
    MAIN SCRIPT EXECUTION SECTION
    
    This section contains the primary script logic that orchestrates the MySQL
    server failover process. It follows these main steps:
    
    1. Initialize script execution with logging
    2. Authenticate to Azure using Managed Identity
    3. Parse the provided resource ID to extract server details
    4. Validate and import required PowerShell modules
    5. Execute the failover operation using REST API
    6. Provide operation summary and results
    
    All operations include comprehensive error handling and logging for Azure
    Automation monitoring and troubleshooting purposes.
#>

# Script execution banner and initial setup
Write-Log "============================================================" "INFO"
Write-Log "AZURE MYSQL FLEXIBLE SERVER FAILOVER SCRIPT" "INFO"
Write-Log "Version: 1.0 | Date: 2025-05-26" "INFO"
Write-Log "============================================================" "INFO"
Write-Log "Starting MySQL Flexible Server Failover operation..." "INFO"
Write-Log "Raw Input: $ResourceIds" "INFO"
$mysqlIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $mysqlIds -or $mysqlIds.Count -eq 0) { throw "No valid MySQL server resource IDs provided" }
Write-Log "Parsed $($mysqlIds.Count) MySQL server id(s)." 'INFO'

if (-not (Connect-ToAzure -ClientId $UAMIClientId)) { throw "Authentication failed" }
if (-not (Initialize-RequiredModules)) { throw "Module init failed" }

$scriptStart = Get-Date

# Capture function definitions for parallel execution
$functionDefs = @"
$(Get-Content Function:\Write-Log -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\ConvertFrom-ResourceId -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Connect-ToAzure -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Initialize-RequiredModules -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Wait-ForAsyncOperation -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Invoke-MySQLServerFailover -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })
"@

$results = $mysqlIds | ForEach-Object -Parallel {
    # Re-create function definitions in parallel runspace
    Invoke-Expression $using:functionDefs
    
    $rid = $_
    Write-Log "Processing MySQL Server: $rid" 'INFO'
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
        
        if ($info.SubscriptionId) { Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null }
        $success = Invoke-MySQLServerFailover -ResourceGroupName $info.ResourceGroup -ServerName $info.ServerName -SubscriptionId $info.SubscriptionId
        $end = Get-Date
        return [pscustomobject]@{ ResourceId=$rid; IsSuccess=$success; ErrorMessage= if ($success) { $null } else { 'MySQL server failover failed' }; StartTime=$start; EndTime=$end; Status= (if ($success) { 'Succeeded' } else { 'Failed' }) }
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
    GlobalError= if ($overallStatus -eq 'Failed') { 'All MySQL server failover operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some operations failed.' } else { $null }
}
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Write-Log "Script execution completed" "INFO"

#endregion Main Script Execution