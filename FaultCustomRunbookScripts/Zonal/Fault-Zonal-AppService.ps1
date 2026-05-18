<#
.SYNOPSIS
    Injects zonal fault for an app service in an Azure Runbook.

.DESCRIPTION
    This Azure Runbook script triggers a zonal fault simulation by using a ARM api.
    
    This script is designed to simulate planned/unplanned outages for resilience testing purposes.
    It performs the following operations:
    1. Authenticates to Azure using Managed Identity
    2. Validates and imports required PowerShell modules
    3. Parses the provided app service resource ID
	  4. Gets the app service environmet ID from the app service resource ID.
    5. Executes the zonal fault simulation on the ASE.
    6. Provides comprehensive logging throughout the process

.PARAMETER ResourceId
    The resource ID for the Azure app service for which zonal fault simulated.
    The resource ID should be in the format:
    "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Web/sites/{appservice-name}"

.EXAMPLE
    # Example 1: Direct execution with resource ID
    .\Fault-Zonal-AppService.ps1 -ResourceId "/subscriptions/2427679b-6638-48e5-8774-6096cd849451/resourceGroups/rabiswaldrillrg/providers/Microsoft.Web/sites/rbdrillasewebapp1"
    
.NOTES
    Author: Azure DevOps Team
    Date: 2025-10-05
    Version: 1.0
    
    Prerequisites:
    - Runbook must run with appropriate permissions (Virtual Machine Contributor role on target app service)
    - Managed Identity or Run As Account must be configured for the Automation Account
    - Target app service must be in a running state
    
    Security Considerations:
    - This script performs destructive operations and should only be used in controlled environments
    - Ensure proper RBAC permissions are in place
    - Consider implementing approval workflows for production environments
    
    Logging:
    - All operations are logged with timestamps and severity levels
    - Logs are written to Azure Automation output streams for monitoring
#>

#Requires -Modules Az.Websites, Az.Accounts
#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma separated resource IDs of the app services")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory = $true, HelpMessage="Zone on which fault will get induced.")]
    [string]$TargetZone,

    [Parameter(Mandatory=$false, HelpMessage="Dummy parameter, this will be ignored")]
    [ValidateNotNullOrEmpty()]
    [long]$Duration,

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
            "INFO"    { Write-Verbose $logEntry}
            "WARNING" { Write-Warning $logEntry }
            "ERROR"   { Write-Error $logEntry }
            "SUCCESS" { Write-Verbose $logEntry}
        }
    }

    <#
    .SYNOPSIS
        Converts an Azure App service resource ID into its components.

    .DESCRIPTION
        This function extracts subscription ID, resource group name, and app service environment name
        from a properly formatted Azure App service resource ID.
        It validates the format and throws an error if the format is invalid.

    .PARAMETER ResourceId
        The Azure resource ID to parse.

    .OUTPUTS
        Returns a hashtable containing:
        - SubscriptionId: The Azure subscription ID
        - ResourceGroup: The resource group name
        - AppEnvName: The app service environment name

    .EXAMPLE
        $resourceInfo = ConvertFrom-ResourceId -ResourceId "/subscriptions/2427679b-6638-48e5-8774-6096cd849451/resourceGroups/rabiswaldrillrg/providers/Microsoft.Web/hostingEnvironments/rbdrillasewebapp1"
        # Returns: @{SubscriptionId="2427679b-6638-48e5-8774-6096cd849451"; ResourceGroup="rabiswaldrillrg"; AppEnvName="rbdrillasewebapp1"}

    .NOTES
        Only supports Azure App service resource IDs.
    #>
    function ConvertFrom-ResourceId {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$ResourceId
        )
        
        if ($ResourceId -match "^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Web/hostingEnvironments/([^/]+)$") {
            return @{
                SubscriptionId = $Matches[1]
                ResourceGroup = $Matches[2]
                AppEnvName = $Matches[3]
            }
        } else {
            throw "Invalid App service resource ID format. Expected format: /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Web/hostingEnvironments/{appservice-name}"
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
        Validates and imports required PowerShell modules for app service operations.

    .DESCRIPTION
        This function checks for the availability of the Az.Websites module and imports it
        if it's available but not currently loaded. This is essential for app service
        operations in Azure Automation environments.

    .OUTPUTS
        Returns $true if the module is available and loaded, $false otherwise.

    .EXAMPLE
        if (Initialize-RequiredModules) {
            Write-Log "Modules ready" "SUCCESS"
        }

    .NOTES
        The Az.Websites module must be imported into the Azure Automation Account
        before this function can succeed.
    #>
    function Initialize-RequiredModules {
        [CmdletBinding()]
        [OutputType([bool])]
        param()
        
        try {
            Write-Log "Checking for required Az.Websites module..." "INFO"
            if (-not (Get-Module -Name "Az.Websites" -ListAvailable)) {
                throw "Az.Websites module is not available in this Automation Account"
            }
            
            if (-not (Get-Module -Name "Az.Websites")) {
                Write-Log "Importing Az.Websites module..." "INFO"
                Import-Module Az.Websites -ErrorAction Stop -Force
            }
            
            Write-Log "Az.Websites module is ready" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Failed to initialize required modules: $($_.Exception.Message)" "ERROR"
            throw "Module initialization failed: $($_.Exception.Message)"
        }
    }

    <#
    .SYNOPSIS
        Performs a zonal fault on the app service.

    .DESCRIPTION
        This function executes a zonal fault simulation on the app service.

    .PARAMETER ResourceGroupName
        The name of the resource group containing the app service.

    .PARAMETER AppEnvName
        The name of the app service environment to simulate the fault on.

    .PARAMETER SubscriptionId
        The Azure subscription ID. If provided and different from current context, 
        the function will switch to this subscription.

    .OUTPUTS
        Returns $true if the restart operation is successful, $false otherwise.

    .EXAMPLE
        $success = Invoke-AppServiceZonalFault -ResourceGroupName "myRG" -AppEnvName "myAppEnv" -SubscriptionId "12345678-1234-1234-1234-123456789012"

    .NOTES
        This operation will simulate a zonal fault on the appservice. App service won't go down.'
    #>
    function Invoke-AppServiceZonalFault {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param (
            [Parameter(Mandatory = $true)]
            [string]$ResourceGroupName,
            
            [Parameter(Mandatory = $true)]
            [string]$AppEnvName,
            
            [Parameter(Mandatory = $false)]
            [string]$SubscriptionId,

            [Parameter(Mandatory = $false)]
            [string]$TargetZone
        )
        
        try {
            Write-Log "Initiating zonal fault simulation on App server '$AppEnvName' in resource group '$ResourceGroupName'..." "INFO"
            
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

            $expirationTime = (Get-Date).AddMinutes(5).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
            $body = @{
                properties = @{
                    faultKind = "Zone"
                    zoneFaultSimulationParameters = @{
                        zones = @($TargetZone)
                    }
                    faultSimulationConstraints = @{
                        expirationTime = $expirationTime
                    }
                }
            } | ConvertTo-Json -Depth 5
            
            $apiVersion = "2023-12-01"
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/hostingEnvironments/$AppEnvName/startFaultSimulation?api-version=$apiVersion"

            Write-Log "Calling App Service zonal fault simulation REST API endpoint... $body " "INFO"

            $headers = @{
                'Authorization' = "Bearer $token"
                'Content-Type' = 'application/json'
            }
            
            $response = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            
            Write-Log "API Response Status Code: $($response.StatusCode)" "INFO"
            
            if ($response.StatusCode -in (200, 202)) {
                Write-Log "Successfully initiated zonal fault on App environment '$AppEnvName' (HTTP $($response.StatusCode))" "INFO"
            }
            else {
                throw "Unexpected status code $($response.StatusCode) from fault simulation API. Response: $($response.Content)"
            }

            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/hostingEnvironments/$AppEnvName/listFaultSimulation?api-version=$apiVersion"
            $response = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -UseBasicParsing -ErrorAction Stop

            if ($response.StatusCode -in (200)) {
                Write-Log "Received the current list of zonal fault on App environment '$AppEnvName' (HTTP $($response.StatusCode))" "INFO"
                $inProgressId = Get-InProgressOperationIds -ResponseBody $response.Content
            }
            else {
                throw "Unexpected status code $($response.StatusCode) from list fault simulation API. Response: $($response.Content)"
            }

            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/hostingEnvironments/$AppEnvName/getFaultSimulation?api-version=$apiVersion"
            
            $completed = Wait-ForFaultSimulationCompletion -StatusUri $uri -Headers $headers -InProgressId $inProgressId
            
            if ($completed) {
                Write-Log "Zonal fault simulation for '$AppEnvName' completed successfully." "SUCCESS"
                return [pscustomobject]@{ IsSuccess = $true; Status = 'Succeeded'; Message = "Zonal fault simulation for '$AppEnvName' completed successfully." }
            }
            else {
                # Prepare the JSON body with the in-progress simulation ID
                $body = @{
                    properties = @{
                        simulationId = $inProgressId
                    }
                } | ConvertTo-Json -Depth 3

                $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/hostingEnvironments/$AppEnvName/stopFaultSimulation?api-version=$apiVersion"
                Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
                Write-Log "Time limit reached or failure observed, Zonal fault simulation for '$AppEnvName' has been stopped." "INFO"
            }
        }
        catch {
            $errorMessage = "Failed to simulate zonal fault on App environment '$AppEnvName': $($_.Exception.Message)"
            Write-Log $errorMessage "ERROR"
            return [pscustomobject]@{ IsSuccess = $false; Status = 'Failed'; Message = $errorMessage }
        }
    }

    function Get-InProgressOperationIds {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$ResponseBody
        )
    
        $operationIds = @()
        try {
            $operations = $ResponseBody | ConvertFrom-Json
            foreach ($item in $operations) {
                if ($item.operation.status -eq 'InProgress') {
                    return $item.operation.id
                }
            }
        } 
        catch {
            Write-Log "Failed to parse response or extract operation IDs: $($_.Exception.Message)." "WARNING"
        }
        return $operationIds
    }

    function Wait-ForFaultSimulationCompletion {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$StatusUri,
            [Parameter(Mandatory = $true)]
            [hashtable]$Headers,
            [Parameter(Mandatory = $true)]
            [string]$InProgressId,
            [Parameter(Mandatory = $false)]
            [int]$TimeoutSeconds = 1200, # 20 minutes
            [Parameter(Mandatory = $false)]
            [int]$PollIntervalSeconds = 30
        )
    
        $startTime = Get-Date
        while ($true) {
            try {
                # Prepare the JSON body with the in-progress simulation ID
                $body = @{
                    properties = @{
                        simulationId = $InProgressId
                    }
                } | ConvertTo-Json -Depth 3

                $response = Invoke-WebRequest -Uri $StatusUri -Method POST -Headers $Headers -Body $body -UseBasicParsing -ErrorAction Stop

                if ($response.StatusCode -eq 200) {
                    $body = $response.Content | ConvertFrom-Json
                    $status = $body.operation.status
                    Write-Log "Current fault simulation status: $status" "INFO"
                    if ($status -eq 'Succeeded') {
                        Write-Log "Fault simulation operation succeeded." "SUCCESS"
                        return $true
                    }
                    elseif ($status -ne 'InProgress') {
                        Write-Log "Fault simulation operation status: $status (not InProgress/Succeeded)" "WARNING"
                        return $false
                    }
                }
                else {
                    Write-Log "Unexpected status code $($response.StatusCode) from fault simulation status API." "WARNING"
                }
            }
            catch {
                Write-Log "Error polling fault simulation status: $($_.Exception.Message)" "ERROR"
            }
    
            $elapsed = (Get-Date) - $startTime
            if ($elapsed.TotalSeconds -ge $TimeoutSeconds) {
                Write-Log "Timeout reached (20 minutes) while waiting for fault simulation completion." "WARNING"
                break
            }
            Start-Sleep -Seconds $PollIntervalSeconds
        }
        return $false
    }

    #endregion Functions
}

# region Main Script Execution
# Set VerbosePreference to Continue to see Write-Verbose logs in automation job streams.
$VerbosePreference = 'Continue'

Write-Verbose "============================================================"
Write-Verbose "AZURE APP SERVICE SIMULATE ZONE FAULT SCRIPT"
Write-Verbose "============================================================"
Write-Verbose "Starting Azure app service zonal fault simulation..."
Write-Verbose "Raw Input: $ResourceIds"

$appServiceIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $appServiceIds -or $appServiceIds.Count -eq 0) { throw "No valid app service resource IDs provided" }
Write-Verbose "Parsed $($appServiceIds.Count) app service id(s)."

# Initial connection check in main thread
try {
    if ($UAMIClientId) {
        Connect-AzAccount -Identity -AccountId $UAMIClientId -ErrorAction Stop | Out-Null
    }
    else {
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    }
    $ctx = Get-AzContext -ErrorAction Stop
    Write-Verbose "Initial connection successful as $($ctx.Account.Id) on subscription $($ctx.Subscription.Name)"
}
catch {
    throw "Initial Azure authentication failed. Please check Managed Identity configuration. Error: $($_.Exception.Message)"
}

$scriptStart = Get-Date

Write-Verbose "Starting parallel processing of $($appServiceIds.Count) app services"

. $functions
$functionsScript = $functions.ToString()

# Process app service IDs in parallel - each runspace handles authentication, ASE lookup, and fault injection
$resultsRaw = $appServiceIds | ForEach-Object -Parallel {
    # Set VerbosePreference in the parallel runspace so Write-Verbose logs appear
    $VerbosePreference = 'Continue'
    
    # Define functions in the parallel runspace
    $functionBlock = [scriptblock]::Create($using:functionsScript)
    . $functionBlock
    
    $appServiceResourceId = $_
    $start = Get-Date
    $result = [pscustomobject]@{
        ResourceId = $appServiceResourceId
        IsSuccess = $false
        ErrorMessage = $null
        StartTime = $start
        EndTime = $start
        Status = 'FailedToStart'
    }

    try {
        Write-Log "Processing App Service resource: $appServiceResourceId" "INFO"
        
        # Parse the App Service resource ID to get subscription, resource group, and app name
        if ($appServiceResourceId -notmatch "^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Web/sites/([^/]+)$") {
            throw "Invalid App Service resource ID format: $appServiceResourceId"
        }
        
        $subscriptionId = $Matches[1]
        $resourceGroup = $Matches[2]
        $appServiceName = $Matches[3]
        
        # Authenticate and set subscription context in one call
        Connect-ToAzure -ClientId $using:UAMIClientId -SubscriptionId $subscriptionId | Out-Null
        
        # Initialize required modules
        Initialize-RequiredModules | Out-Null
        
        # Get the ASE ID from the App Service
        Write-Log "Getting ASE ID for App Service '$appServiceName' in resource group '$resourceGroup'" "INFO"
        $hostingEnvProfile = Get-AzWebApp -Name $appServiceName -ResourceGroupName $resourceGroup -ErrorAction Stop | Select-Object -ExpandProperty HostingEnvironmentProfile
        
        if (-not $hostingEnvProfile -or -not $hostingEnvProfile.Id) {
            throw "App Service '$appServiceName' is not hosted on an App Service Environment (ASE). Zonal fault simulation is only supported for ASE-hosted apps."
        }
        
        $aseResourceId = $hostingEnvProfile.Id
        Write-Log "Found ASE resource ID: $aseResourceId" "INFO"
        
        # Parse the ASE resource ID
        $aseInfo = ConvertFrom-ResourceId -ResourceId $aseResourceId
        
        # Execute the zonal fault simulation
        $faultResult = Invoke-AppServiceZonalFault -ResourceGroupName $aseInfo.ResourceGroup -AppEnvName $aseInfo.AppEnvName -SubscriptionId $aseInfo.SubscriptionId -TargetZone $using:TargetZone
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

# Ensure resultsRaw is an array
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
    GlobalError= if ($overallStatus -eq 'Failed') { 'All zone fault simulation on AppService operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some operations failed.' } else { $null }
}
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Fail the runbook if any resource could not be faulted
if ($failureCount -gt 0) {
    $errorMsg = "Runbook failed: $failureCount out of $($appServiceIds.Count) AppService(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Verbose "All zone fault simulation on AppService operations completed successfully."

#endregion Main Script Execution
