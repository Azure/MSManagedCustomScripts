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
#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma separated resource IDs of the Azure MySQL Flexible Servers")]
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
        "INFO"    { Write-Information $logEntry -InformationAction Continue }
        "WARNING" { Write-Warning $logEntry }
        "ERROR"   { Write-Error $logEntry }
        "SUCCESS" { Write-Information $logEntry -InformationAction Continue }
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
        throw "Module initialization failed: $($_.Exception.Message)"
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
                    $errorMessage = "Async operation failed."
                    if ($statusObj.error) {
                        $errorMessage += " Details: $($statusObj.error | ConvertTo-Json -Depth 2 -Compress)"
                    }
                    Write-Log $errorMessage "ERROR"
                    throw $errorMessage
                }
                "canceled" {
                    Write-Log "Async operation was canceled" "ERROR"
                    throw "Async operation was canceled"
                }
                "inprogress" {
                    Write-Log "Operation still in progress. Continuing to poll..." "INFO"
                }
                "running" {
                    Write-Log "Operation still in progress. Continuing to poll..." "INFO"
                }
                default {
                    Write-Log "Unknown operation status: $status. Continuing to poll..." "WARNING"
                }
            }
        }
        else {
            Write-Log "Unexpected response status code: $($statusResponse.StatusCode). Response content: $($statusResponse.Content)" "ERROR"
            throw "Unexpected response status code: $($statusResponse.StatusCode)"
        }
    } while (Get-Date -lt $maxWaitTime)
    
    Write-Log "Async operation polling timed out after $MaxWaitTimeMinutes minutes" "ERROR"
    return $false
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
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServerName,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    try {
        Write-Log "Initiating unplanned failover for MySQL server '$ServerName' in resource group '$ResourceGroupName'..." "INFO"
        
        $accessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
        
        if ($accessToken.Token -is [System.Security.SecureString]) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessToken.Token)
            try {
                $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        } else {
            $token = $accessToken.Token
        }
        
        $apiVersion = "2023-12-30"
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DBforMySQL/flexibleServers/$ServerName/failover?api-version=$apiVersion"
        
        Write-Log "Calling MySQL failover REST API endpoint..." "INFO"
        
        $headers = @{
            'Authorization' = "Bearer $token"
            'Content-Type' = 'application/json'
        }
        
        $response = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -UseBasicParsing -ErrorAction Stop
        
        Write-Log "API Response Status Code: $($response.StatusCode)" "INFO"
        
        if ($response.StatusCode -in (200, 202)) {
            Write-Log "Successfully initiated failover for MySQL server '$ServerName' (HTTP $($response.StatusCode))" "INFO"
            
            $asyncOperationUrl = $null
            if ($response.Headers['Azure-AsyncOperation']) {
                $asyncOperationUrl = @($response.Headers['Azure-AsyncOperation'])[0]
            }
            elseif ($response.Headers['azure-asyncoperation']) {
                $asyncOperationUrl = @($response.Headers['azure-asyncoperation'])[0]
            }
            elseif ($response.Headers['Location']) {
                $asyncOperationUrl = @($response.Headers['Location'])[0]
                Write-Log "Azure-AsyncOperation header not found. Falling back to Location header for polling." "WARNING"
            }

            if (-not [string]::IsNullOrWhiteSpace($asyncOperationUrl)) {
                Write-Log "Polling async status endpoint: $asyncOperationUrl" "INFO"
                Wait-ForAsyncOperation -AsyncOperationUrl $asyncOperationUrl -Headers $headers
            }
            else {
                Write-Log "Async operation status URL not provided by service; skipping polling." "WARNING"
            }
            
            Write-Log "Failover operation for '$ServerName' completed successfully." "SUCCESS"
            return [pscustomobject]@{ IsSuccess = $true; Status = 'Succeeded'; Message = $null }
        }
        else {
            throw "Unexpected status code $($response.StatusCode) from failover API. Response: $($response.Content)"
        }
    }
    catch {
        $errorMessage = "Failed to failover MySQL server '$ServerName': $($_.Exception.Message)"
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
Write-Information "AZURE MYSQL FLEXIBLE SERVER FAILOVER SCRIPT"
Write-Information "============================================================"
Write-Information "Starting MySQL Flexible Server Failover operation..."
Write-Information "Raw Input: $ResourceIds"
$mysqlIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $mysqlIds -or $mysqlIds.Count -eq 0) { throw "No valid MySQL server resource IDs provided" }
Write-Information "Parsed $($mysqlIds.Count) MySQL server id(s)."

# Initial connection check in main thread
try {
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

$scriptStart = Get-Date

Write-Information "Starting parallel processing of $($mysqlIds.Count) MySQL servers"

$functionsScript = $functions.ToString()

$resultsRaw = $mysqlIds | ForEach-Object -Parallel {
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

        $faultResult = Invoke-MySQLServerFailover -ResourceGroupName $info.ResourceGroup -ServerName $info.ServerName -SubscriptionId $info.SubscriptionId
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
        Write-Information "Captured unexpected output item of type '$($item.GetType().FullName)'." -InformationAction Continue
    }
}

if ($unexpectedOutputs.Count -gt 0) {
    Write-Information "Skipping $($unexpectedOutputs.Count) unexpected output item(s) from parallel processing." -InformationAction Continue
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
    GlobalError= if ($overallStatus -eq 'Failed') { 'All MySQL server failover operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some operations failed.' } else { $null }
}
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Fail the runbook if any resource could not be faulted
if ($failureCount -gt 0) {
    $errorMsg = "Runbook failed: $failureCount out of $($mysqlIds.Count) MySQL server(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Information "All MySQL server failover operations completed successfully." -InformationAction Continue

#endregion Main Script Execution