# SYNOPSIS
#   Shuts down and recovers zoned node pools of an AKS cluster using Automation Account identity.
#
# DESCRIPTION
#   This runbook accepts one or more AKS cluster resource IDs (comma separated) and a duration in minutes.
#   It authenticates via Managed Identity, identifies node pools pinned to any availability zone,
#   scales them to zero to simulate failure, waits for the specified duration, and then restores original counts.
#   Outputs a JSON object matching RunbookExecutionResult contract for aggregated results.
#
#   Version: 1.1 (PS7 Migration)
#
# PARAMETERS
#   -ResourceIds: Comma-separated AKS cluster resource IDs.
#   -SubscriptionToTargetZone: JSON-serialized dictionary mapping each involved subscription id to the logical
#                              availability zone to fault (e.g. '{"sub1":"1","sub2":"2"}'). If a subscription's zone
#                              value is empty or missing, every resource in that subscription is still faulted but
#                              without zone targeting.
#   -TargetZone: Optional fallback zone string applied to every resource when SubscriptionToTargetZone is not
#                supplied. Ignored when SubscriptionToTargetZone is provided.
#   -DurationInMinutes: Time in minutes to wait before restoring node pool counts.
#
# EXAMPLE
#   .\Fault-AksZones.ps1 -ResourceIds "/subscriptions/<sub>/.../managedClusters/myAKS" `
#       -SubscriptionToTargetZone '{"<sub>":"1"}' -DurationInMinutes 15

#Requires -Modules Az.Aks, Az.Accounts
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Comma-separated AKS cluster resource IDs.")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$false, HelpMessage="JSON-serialized dictionary mapping each involved subscription id to the logical availability zone to fault (e.g. '{""sub1"":""1"",""sub2"":""2""}'). When supplied, takes precedence over TargetZone. If a subscription's zone value is empty or missing, every resource in that subscription is still faulted but without zone targeting.")]
    [object]$SubscriptionToTargetZone,

    [Parameter(Mandatory=$false, HelpMessage="Fallback logical availability zone applied to every resource when SubscriptionToTargetZone is not supplied. Ignored when SubscriptionToTargetZone is provided.")]
    [string]$TargetZone,

    [Parameter(Mandatory=$true, HelpMessage="Duration in minutes before restoring node pools")]
    [ValidateRange(1,1440)]
    [Alias("DurationInMinutes")]
    [int]$Duration,

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
    #region Logging Function
    function Write-Log {
        param(
            [string]$Message,
            [ValidateSet("INFO","WARNING","ERROR","SUCCESS")]
            [string]$Level = "INFO"
        )
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $entry = "[$ts] [$Level] $Message"
        switch ($Level) {
            "INFO"    { Write-Verbose $entry }
            "WARNING" { Write-Warning $entry }
            "ERROR"   { Write-Error $entry }
            "SUCCESS" { Write-Verbose $entry }
        }
    }
    #endregion

    #region ResourceId Parser
    function ConvertFrom-ResourceIdAKS {
        param(
            [string]$ResourceId
        )
        if ($ResourceId -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.ContainerService/managedClusters/([^/]+)$") {
            return @{ SubscriptionId=$Matches[1]; ResourceGroup=$Matches[2]; ClusterName=$Matches[3] }
        }
        throw "Invalid AKS resource ID format."
    }
    #endregion

    #region Authenticate and Module Init
    function Connect-ToAzure {
        param(
            [string]$ClientId,
            [string]$SubscriptionId
        )
        try
        {
            if ([string]::IsNullOrEmpty($ClientId))
            {
                Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
                Connect-AzAccount -Identity -Verbose:$false -ErrorAction Stop | Out-Null
            }
            else
            {
                Write-Log "Authenticating to Azure via User-Assigned Managed Identity (ClientId: $ClientId)" "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -Verbose:$false -ErrorAction Stop | Out-Null
            }

            # If a subscription ID is provided, set the context to that subscription immediately
            if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
                Write-Log "Setting subscription context to $SubscriptionId" "INFO"
                Set-AzContext -SubscriptionId $SubscriptionId -Verbose:$false -ErrorAction Stop | Out-Null
            }

            $ctx = Get-AzContext -ErrorAction Stop
            Write-Log "Connected as $($ctx.Account.Id) on subscription $($ctx.Subscription.Name)" "SUCCESS"
            return $true
        } catch {
            Write-Log "Azure authentication failed: $($_.Exception.Message)" "ERROR"
            # This is a terminating error for the thread, so re-throw
            throw "Azure authentication failed: $($_.Exception.Message)"
        }
    }

    function Initialize-Modules {
        try {
            Write-Log "Checking Az.Aks module..." "INFO"
            if (-not (Get-Module -Name Az.Aks -ListAvailable 4>$null)) {
                throw "Az.Aks module not available"
            }
            if (-not (Get-Module -Name Az.Aks)) {
                Write-Log "Importing Az.Aks module..." "INFO"
                Import-Module Az.Aks -ErrorAction Stop 4>$null
            }
            Write-Log "Az.Aks module ready" "SUCCESS"
            return $true
        } catch {
            Write-Log "Module initialization failed: $($_.Exception.Message)" "ERROR"
            throw "Module initialization failed: $($_.Exception.Message)"
        }
    }
    #endregion

    #region Shutdown and Recovery Logic
    function Invoke-AksZoneFault {
        param(
            [string]$ResourceGroup,
            [string]$ClusterName,
            [Alias("DurationInMinutes")]
            [int]$Duration,
            [string]$TargetZone
        )
        try {
            Write-Log "Retrieving node pools for cluster '$ClusterName' in RG '$ResourceGroup'" "INFO"
            $nodePools = Get-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -ErrorAction Stop

            $zonedPools = $nodePools | Where-Object { $_.AvailabilityZones -and $_.AvailabilityZones.Count -gt 0 }
            $targetZoneTrimmed = if ([string]::IsNullOrWhiteSpace($TargetZone)) { $null } else { $TargetZone.Trim() }
            if ($targetZoneTrimmed) {
                $zonedPools = $zonedPools | Where-Object { $_.AvailabilityZones -contains $targetZoneTrimmed }
                if (-not $zonedPools) {
                    Write-Log "No zoned node pools found for cluster '$ClusterName' in target zone '$targetZoneTrimmed'. Nothing to fault." "WARNING"
                    return [pscustomobject]@{ IsSuccess = $false; Status = 'Skipped'; Message = "No zoned node pools found in target zone '$targetZoneTrimmed'."; TargetZone = $targetZoneTrimmed }
                }
            }
            if (-not $zonedPools) {
                Write-Log "No zoned node pools found for cluster '$ClusterName'. Nothing to fault." "WARNING"
                # Returning a custom object to indicate skipped status
                return [pscustomobject]@{ IsSuccess = $false; Status = 'Skipped'; Message = 'No zoned node pools found.' }
            }

            # Filter out system node pools - they cannot be scaled to 0 nodes
            $systemPools = $zonedPools | Where-Object { $_.Mode -eq 'System' }
            $userPools = $zonedPools | Where-Object { $_.Mode -ne 'System' }
            
            if ($systemPools) {
                $systemPoolNames = ($systemPools | ForEach-Object { $_.Name }) -join ', '
                Write-Log "Skipping system node pool(s) '$systemPoolNames' - system pools cannot be scaled to 0 nodes." "WARNING"
            }
            
            if (-not $userPools) {
                Write-Log "No user node pools available to fault for cluster '$ClusterName' (only system pools found which cannot be scaled to 0)." "WARNING"
                return [pscustomobject]@{ IsSuccess = $false; Status = 'Skipped'; Message = 'No user node pools available to fault. System pools cannot be scaled to 0.' }
            }
            
            # Use only user pools for faulting
            $zonedPools = $userPools

            # Record original counts and autoscale settings, then scale down
            $originalSettings = @{}
            foreach ($np in $zonedPools) {
                $originalSettings[$np.Name] = @{
                    Count = $np.Count
                    EnableAutoScaling = $np.EnableAutoScaling
                    MinCount = if ($np.EnableAutoScaling -and $np.MinCount) { $np.MinCount } else { $null }
                    MaxCount = $np.MaxCount
                }

                if ($np.EnableAutoScaling) {
                    Write-Log "Disabling autoscale for node pool '$($np.Name)'" "INFO"
                    Update-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -Name $np.Name `
                        -EnableAutoScaling:$false -ErrorAction Stop
                }

                Write-Log "Scaling down node pool '$($np.Name)' (zones: $($np.AvailabilityZones -join ',')) from $($np.Count) to 0" "INFO"
                Update-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -Name $np.Name -NodeCount 0 -ErrorAction Stop
            }

            Write-Log "Node pools for cluster '$ClusterName' shut down. Waiting $Duration minutes before restore." "INFO"
            Start-Sleep -Seconds ($Duration * 60)

            # Restore original counts and autoscale settings
            foreach ($name in $originalSettings.Keys) {
                $settings = $originalSettings[$name]

                Write-Log "Restoring node pool '$name' to $($settings.Count) nodes" "INFO"
                Update-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -Name $name -NodeCount $settings.Count -ErrorAction Stop

                if ($settings.EnableAutoScaling -and $null -ne $settings.MinCount -and $null -ne $settings.MaxCount) {
                    Write-Log "Re-enabling autoscale for node pool '$name' (Min: $($settings.MinCount), Max: $($settings.MaxCount))" "INFO"
                    Update-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -Name $name `
                        -EnableAutoScaling:$true -MinCount $settings.MinCount -MaxCount $settings.MaxCount -ErrorAction Stop
                }
            }

            Write-Log "Node pools for cluster '$ClusterName' restored successfully" "SUCCESS"
            return [pscustomobject]@{ IsSuccess = $true; Status = 'Succeeded'; Message = $null }
        } catch {
            $errorMessage = "Error during AKS zone fault operation for cluster '$ClusterName': $($_.Exception.Message)"
            Write-Log $errorMessage "ERROR"
            # This is a terminating error for the fault logic, return failure object
            return [pscustomobject]@{ IsSuccess = $false; Status = 'Failed'; Message = $errorMessage }
        }
    }
    #endregion
}

#region Main
# Set VerbosePreference to Continue to see Write-Verbose logs in automation job streams.
# Suppress engine-level module-load verbose noise (PowerShell emits "Loading module"
# and "Importing cmdlet" while $VerbosePreference is Continue, regardless of -Verbose:$false).
# Pre-import Az.Accounts silently, then enable verbose so our own Write-Verbose logs appear.
$VerbosePreference = 'SilentlyContinue'
Import-Module Az.Accounts -ErrorAction Stop
$VerbosePreference = 'Continue'

Write-Verbose "===== Starting AKS Zone Fault Injection ====="
$loggedSubscriptionToTargetZone = if ($null -eq $SubscriptionToTargetZone) { '<null>' } elseif ($SubscriptionToTargetZone -is [string]) { $SubscriptionToTargetZone } else { $SubscriptionToTargetZone | ConvertTo-Json -Compress -Depth 5 }
Write-Verbose "Raw Input: ResourceIds=$ResourceIds; SubscriptionToTargetZone=$loggedSubscriptionToTargetZone; TargetZone=$TargetZone"

$AksTargetList = Get-ResourceTargets -ResourceIds $ResourceIds -SubscriptionToTargetZone $SubscriptionToTargetZone -TargetZone $TargetZone
Write-Verbose "Parsed $($AksTargetList.Count) AKS resource target(s)."

$scriptStart = Get-Date
$operationObjects = @()

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

Write-Verbose "Starting parallel processing of $($AksTargetList.Count) AKS clusters"

$functionsScript = $functions.ToString()

$operationObjectsRaw = $AksTargetList | ForEach-Object -Parallel {
    # Set VerbosePreference in the parallel runspace so Write-Verbose logs appear
    # Suppress engine-level module-load verbose noise (PowerShell emits "Loading module"
    # and "Importing cmdlet" while $VerbosePreference is Continue, regardless of -Verbose:$false).
    # Pre-import Az.Accounts silently, then enable verbose so our own Write-Verbose logs appear.
    $VerbosePreference = 'SilentlyContinue'
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Aks -ErrorAction Stop
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
        $info = ConvertFrom-ResourceIdAKS -ResourceId $rid

        # Authenticate and initialize modules in the parallel runspace, passing the target subscription
        Connect-ToAzure -ClientId $using:UAMIClientId -SubscriptionId $info.SubscriptionId | Out-Null
        Initialize-Modules | Out-Null

        # Execute the fault operation
        $faultResult = Invoke-AksZoneFault -ResourceGroup $info.ResourceGroup -ClusterName $info.ClusterName -DurationInMinutes $using:Duration -TargetZone $targetZone
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

$operationObjectsRaw = @($operationObjectsRaw | Where-Object { $_ })
$operationObjects = @()
$unexpectedOutputs = @()

foreach ($item in $operationObjectsRaw) {
    if ($item -is [pscustomobject] -and $item.PSObject.Properties['ResourceId']) {
        $operationObjects += $item
    }
    else {
        $unexpectedOutputs += $item
        Write-Verbose "Captured unexpected output item of type '$($item.GetType().FullName)'."
    }
}

if ($unexpectedOutputs.Count -gt 0) {
    Write-Verbose "Skipping $($unexpectedOutputs.Count) unexpected output item(s) from parallel processing."
}

if ($operationObjects.Count -eq 0 -and $unexpectedOutputs.Count -gt 0) {
    Write-Warning "Parallel processing returned no valid result objects. Check unexpected outputs for details."
}


$scriptEnd = Get-Date
$successCount = ($operationObjects | Where-Object { $_.IsSuccess }).Count
$failureCount = ($operationObjects | Where-Object { -not $_.IsSuccess }).Count
$failureCount += $unexpectedOutputs.Count
$overallStatus = if ($failureCount -eq 0) { 'Success' } elseif ($successCount -gt 0) { 'PartialSuccess' } else { 'Failed' }

$resourceResults = @()
foreach ($op in $operationObjects) {
    if (-not $op) { continue }
    $endTime = if ($op.EndTime) { $op.EndTime } elseif ($op.StartTime) { $op.StartTime } else { Get-Date }
    $startTime = if ($op.StartTime) { $op.StartTime } else { $endTime }
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
    if (-not $op.IsSuccess) {
        $err = @{ ErrorCode='FailedToFaultResource'; Message=$op.ErrorMessage; Details=$op.ErrorMessage; Category=$op.Status; IsRetryable=$false }
    }
    $processedAtUtc = $endTime.ToUniversalTime()
    $resourceResults += @{ ResourceId=$op.ResourceId; IsSuccess=$op.IsSuccess; Error=$err; ProcessedAt=$processedAtUtc; ProcessingDurationMs=$durationMs; Metadata=@{ Status=$op.Status } }
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
    GlobalError= if ($overallStatus -eq 'Failed') { 'All AKS zone fault operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some AKS zone fault operations failed.' } else { $null }
}
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Fail the runbook if any resource could not be faulted
if ($failureCount -gt 0) {
    $errorMsg = "Runbook failed: $failureCount out of $($AksTargetList.Count) AKS cluster(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Verbose "All AKS zone fault operations completed successfully."

#endregion