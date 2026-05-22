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

.PARAMETER ResourceIds
    Comma-separated App Service resource IDs. Each resource id should be in the format:
    "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Web/sites/{appservice-name}"

.PARAMETER SubscriptionToTargetZone
    JSON-serialized dictionary mapping each involved subscription id to the logical availability zone to fault.
    Example: '{"<subscriptionId>":"<zone>","<subscriptionId2>":"<zone2>"}'.
    If a subscription's zone value is empty or missing, every resource in that subscription is still faulted but
    without zone targeting (zone-aware fault routines fall back to acting on the entire resource).
.PARAMETER TargetZone
    Optional fallback logical availability zone applied to every resource when SubscriptionToTargetZone is
    not supplied. Ignored when SubscriptionToTargetZone is provided.

#>

#Requires -Modules Az.Websites, Az.Accounts
#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Comma-separated App Service resource IDs.")]
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
        propagated for every resource. NOTE: this script's Invoke-AppServiceZonalFault
        requires a non-empty target zone (the ARM startFaultSimulation API requires a
        zones array), so for App Service an empty TargetZone here will surface as a
        per-resource Failed result with a clear error message rather than a silent skip.
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
        # NOTE: this script's Invoke-AppServiceZonalFault requires a non-empty target zone (the
        # ARM startFaultSimulation API requires a zones array), so an empty TargetZone here will
        # surface as a per-resource Failed result with a clear error rather than a silent skip.
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
                Connect-AzAccount -Identity -Verbose:$false -ErrorAction Stop | Out-Null
            } else {
                Write-Log "Authenticating to Azure using User-Assigned Managed Identity (ClientId: $ClientId)..." "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -Verbose:$false -ErrorAction Stop | Out-Null
            }

            # If a subscription ID is provided, set the context to that subscription immediately
            if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
                Write-Log "Setting subscription context to $SubscriptionId" "INFO"
                Set-AzContext -SubscriptionId $SubscriptionId -Verbose:$false -ErrorAction Stop | Out-Null
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
            if (-not (Get-Module -Name "Az.Websites" -ListAvailable 4>$null)) {
                throw "Az.Websites module is not available in this Automation Account"
            }
            
            if (-not (Get-Module -Name "Az.Websites")) {
                Write-Log "Importing Az.Websites module..." "INFO"
                Import-Module Az.Websites -Force -ErrorAction Stop 4>$null
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

    .PARAMETER TargetZone
        REQUIRED. The logical availability zone (e.g. '1', '2', '3') to fault. The ARM
        startFaultSimulation API for App Service Environments requires a non-empty zone,
        so this parameter cannot be empty even when the runbook-level SubscriptionToTargetZone
        or TargetZone allow empty values for other resource types.

    .OUTPUTS
        Returns $true if the restart operation is successful, $false otherwise.

    .EXAMPLE
        $success = Invoke-AppServiceZonalFault -ResourceGroupName "myRG" -AppEnvName "myAppEnv" -SubscriptionId "12345678-1234-1234-1234-123456789012" -TargetZone "1"

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

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$TargetZone
        )
        
        try {
            # Defensive runtime check in addition to ValidateNotNullOrEmpty above, in case a
            # caller binds the parameter dynamically with an explicit empty/whitespace string.
            if ([string]::IsNullOrWhiteSpace($TargetZone)) {
                throw "TargetZone is required for App Service zonal fault simulation; supply TargetZone or a non-empty value for the subscription in SubscriptionToTargetZone."
            }

            Write-Log "Initiating zonal fault simulation on App server '$AppEnvName' in resource group '$ResourceGroupName' (zone '$TargetZone')..." "INFO"
            
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
# Suppress engine-level module-load verbose noise (PowerShell emits "Loading module"
# and "Importing cmdlet" while $VerbosePreference is Continue, regardless of -Verbose:$false).
# Pre-import Az.Accounts silently, then enable verbose so our own Write-Verbose logs appear.
$VerbosePreference = 'SilentlyContinue'
Import-Module Az.Accounts -ErrorAction Stop
$VerbosePreference = 'Continue'

Write-Verbose "============================================================"
Write-Verbose "AZURE APP SERVICE SIMULATE ZONE FAULT SCRIPT"
Write-Verbose "============================================================"
Write-Verbose "Starting Azure app service zonal fault simulation..."
$loggedSubscriptionToTargetZone = if ($null -eq $SubscriptionToTargetZone) { '<null>' } elseif ($SubscriptionToTargetZone -is [string]) { $SubscriptionToTargetZone } else { $SubscriptionToTargetZone | ConvertTo-Json -Compress -Depth 5 }
Write-Verbose "Raw Input: ResourceIds=$ResourceIds; SubscriptionToTargetZone=$loggedSubscriptionToTargetZone; TargetZone=$TargetZone"

$appServiceTargets = Get-ResourceTargets -ResourceIds $ResourceIds -SubscriptionToTargetZone $SubscriptionToTargetZone -TargetZone $TargetZone
Write-Verbose "Parsed $($appServiceTargets.Count) app service target(s)."

# Initial connection check in main thread
try {
    if ($UAMIClientId) {
        Connect-AzAccount -Identity -AccountId $UAMIClientId -Verbose:$false -ErrorAction Stop | Out-Null
    }
    else {
        Connect-AzAccount -Identity -Verbose:$false -ErrorAction Stop | Out-Null
    }
    $ctx = Get-AzContext -ErrorAction Stop
    Write-Verbose "Initial connection successful as $($ctx.Account.Id) on subscription $($ctx.Subscription.Name)"
}
catch {
    throw "Initial Azure authentication failed. Please check Managed Identity configuration. Error: $($_.Exception.Message)"
}

$scriptStart = Get-Date

Write-Verbose "Starting parallel processing of $($appServiceTargets.Count) app services"

. $functions
$functionsScript = $functions.ToString()

# Process app service targets in parallel - each runspace handles authentication, ASE lookup, and fault injection
$resultsRaw = $appServiceTargets | ForEach-Object -Parallel {
    # Set VerbosePreference in the parallel runspace so Write-Verbose logs appear
    # Suppress engine-level module-load verbose noise (PowerShell emits "Loading module"
    # and "Importing cmdlet" while $VerbosePreference is Continue, regardless of -Verbose:$false).
    # Pre-import Az.Accounts silently, then enable verbose so our own Write-Verbose logs appear.
    $VerbosePreference = 'SilentlyContinue'
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Websites -ErrorAction Stop
    $VerbosePreference = 'Continue'
    
    # Define functions in the parallel runspace
    $functionBlock = [scriptblock]::Create($using:functionsScript)
    . $functionBlock
    
    $entry = $_
    $appServiceResourceId = $entry.ResourceId
    $targetZone = $entry.TargetZone
    $targetZoneLabel = if ([string]::IsNullOrWhiteSpace($targetZone)) { '<none - faulting without zone targeting>' } else { $targetZone }
    Write-Verbose "Targeting zone '$targetZoneLabel' for resource $($entry.ResourceId)"
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
        $faultResult = Invoke-AppServiceZonalFault -ResourceGroupName $aseInfo.ResourceGroup -AppEnvName $aseInfo.AppEnvName -SubscriptionId $aseInfo.SubscriptionId -TargetZone $targetZone
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
    $errorMsg = "Runbook failed: $failureCount out of $($appServiceTargets.Count) AppService(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Verbose "All zone fault simulation on AppService operations completed successfully."

#endregion Main Script Execution
