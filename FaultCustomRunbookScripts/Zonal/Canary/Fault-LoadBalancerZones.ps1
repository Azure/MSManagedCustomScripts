# SYNOPSIS
#   Performs fault injection by overriding health probes on one or more Azure Load Balancers using Automation Account identity.
#
# DESCRIPTION
#   This runbook accepts a Load Balancer resource ID and uses Managed Identity to authenticate.
#   It locates all health probes associated with backend pools that have VMs or VMSS instances pinned to any availability zone,
#   and overrides their settings to simulate failure (e.g., by changing probe port to an invalid port).
#   This helps test zone resiliency by forcing traffic away from zoned backends.
#
#   Version: 1.1 (PS7 Migration)
#
# PARAMETERS
#   -ResourceIds: Comma-separated Load Balancer resource IDs.
#   -SubscriptionToTargetZone: JSON-serialized dictionary mapping each involved subscription id to the logical
#                              availability zone to fault (e.g. '{"sub1":"1","sub2":"2"}'). If a subscription's zone
#                              value is empty or missing, every resource in that subscription is still faulted but
#                              without zone targeting.
#   -TargetZone: Optional fallback zone string applied to every resource when SubscriptionToTargetZone is not
#                supplied. Ignored when SubscriptionToTargetZone is provided.
#   -UAMIClientId: Optional. Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.
#
# EXAMPLE
#   .\Fault-LoadBalancerZones.ps1 -ResourceIds "/subscriptions/xxx/.../loadBalancers/myLoadBalancer" `
#       -SubscriptionToTargetZone '{"xxx":"1"}' -Duration 5

#Requires -Modules Az.Network, Az.Accounts
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Comma-separated Load Balancer resource IDs.")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$false, HelpMessage="JSON-serialized dictionary mapping each involved subscription id to the logical availability zone to fault (e.g. '{""sub1"":""1"",""sub2"":""2""}'). When supplied, takes precedence over TargetZone. If a subscription's zone value is empty or missing, every resource in that subscription is still faulted but without zone targeting.")]
    [object]$SubscriptionToTargetZone,

    [Parameter(Mandatory=$false, HelpMessage="Fallback logical availability zone applied to every resource when SubscriptionToTargetZone is not supplied. Ignored when SubscriptionToTargetZone is provided.")]
    [string]$TargetZone,

    [Parameter(Mandatory=$true, HelpMessage="Duration in minutes to keep health probes down (e.g. '5' for 5 minutes)")]
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
    function ConvertFrom-ResourceIdLB {
        param(
            [Parameter(Mandatory=$true)] [string]$ResourceId
        )
        if ($ResourceId -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Network/loadBalancers/([^/]+)$") {
            return @{ SubscriptionId=$Matches[1]; ResourceGroup=$Matches[2]; LBName=$Matches[3] }
        }
        throw "Invalid Load Balancer resource ID format."
    }
    #endregion

    #region Authenticate and Module Init
    function Connect-ToAzure {
        param(
            [string]$ClientId,
            [string]$SubscriptionId
        )
        try {
            if ([string]::IsNullOrEmpty($ClientId)) {
                Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
                Connect-AzAccount -Identity -Verbose:$false -ErrorAction Stop | Out-Null
            } else {
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
            throw "Azure authentication failed: $($_.Exception.Message)"
        }
    }

    function Initialize-Modules {
        try {
            Write-Log "Checking Az.Network module..." "INFO"
            if (-not (Get-Module -Name Az.Network -ListAvailable 4>$null)) {
                throw "Az.Network module not available"
            }
            if (-not (Get-Module -Name Az.Network)) {
                Write-Log "Importing Az.Network module..." "INFO"
                Import-Module Az.Network -ErrorAction Stop 4>$null
            }
            Write-Log "Az.Network module ready" "SUCCESS"
            return $true
        } catch {
            Write-Log "Module initialization failed: $($_.Exception.Message)" "ERROR"
            throw "Module initialization failed: $($_.Exception.Message)"
        }
    }
    #endregion

    #region Override Health Probes
    function Override-LoadBalancerHealthProbes {
        param(
            [string]$ResourceGroup,
            [string]$LBName,
            [TimeSpan]$Duration,
            [string]$TargetZone
        )
        try {
            Write-Log "Retrieving Load Balancer '$LBName' in RG '$ResourceGroup'" "INFO"
            $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroup -Name $LBName -ErrorAction Stop

            # Identify probes to override by finding probes associated with zoned backends
            $probesToOverride = @()
            $backendPools = $lb.BackendAddressPools
            $targetZoneTrimmed = if ([string]::IsNullOrWhiteSpace($TargetZone)) { $null } else { $TargetZone.Trim() }
            if ($null -ne $backendPools) {
                foreach ($pool in $backendPools) {
                    # A backend pool can have multiple NICs. Check each one.
                    $backendIpConfigs = $pool.BackendIPConfigurations
                    if ($null -ne $backendIpConfigs) {
                        foreach ($ipConfig in $backendIpConfigs) {
                            $nic = Get-AzNetworkInterface -ResourceId $ipConfig.Id -ErrorAction SilentlyContinue
                            if ($nic -and $nic.Zones) {
                                $nicZones = $nic.Zones
                                $zoneMatch = $true
                                if ($targetZoneTrimmed) {
                                    $zoneMatch = $nicZones -contains $targetZoneTrimmed
                                }
                                if ($zoneMatch) {
                                    Write-Log "Found zoned backend NIC '$($nic.Name)' in pool '$($pool.Name)' (zones: $($nic.Zones -join ','))" "INFO"
                                    # Find the probe associated with this pool via load balancing rules
                                    $rules = $lb.LoadBalancingRules | Where-Object { $_.BackendAddressPool.Id -eq $pool.Id }
                                    if ($rules) {
                                        $probeIds = $rules.Probe.Id | Select-Object -Unique
                                        $probesToOverride += $lb.Probes | Where-Object { $probeIds -contains $_.Id }
                                    }
                                    # Break from inner loop once a zoned NIC is found for this pool
                                    break
                                }
                            }
                        }
                    }
                }
            }

            $uniqueProbesToOverride = $probesToOverride | Select-Object -Unique
            if (-not $uniqueProbesToOverride) {
                Write-Log "No health probes found for zoned backends on LB '$LBName'. Nothing to override." "WARNING"
                return [pscustomobject]@{ IsSuccess = $true; Status = 'Skipped'; Message = 'No health probes found for zoned backends.' }
            }

            # Capture original probe settings before override
            $originalProbes = @{}
            foreach ($probe in $uniqueProbesToOverride) {
                $originalProbes[$probe.Name] = $probe
                Write-Log "Staging override for probe '$($probe.Name)'" "INFO"
                Set-AzLoadBalancerProbeConfig -LoadBalancer $lb -Name $probe.Name -Protocol $probe.Protocol -Port 9999 -IntervalInSeconds $probe.IntervalInSeconds -ProbeCount $probe.ProbeCount -ErrorAction Stop
            }

            # Commit changes
            Write-Log "Updating Load Balancer '$LBName' to apply probe overrides" "INFO"
            Set-AzLoadBalancer -LoadBalancer $lb -ErrorAction Stop | Out-Null
            Write-Log "Health probes for '$LBName' overridden successfully" "SUCCESS"

            # Wait for specified duration before restoring
            Write-Log "Sleeping for $($Duration.TotalMinutes) minutes before restoring probes on '$LBName'" "INFO"
            Start-Sleep -Seconds $Duration.TotalSeconds

            # Re-enable original health probes
            Write-Log "Restoring original health probes for '$LBName'" "INFO"
            foreach ($probeName in $originalProbes.Keys) {
                $orig = $originalProbes[$probeName]
                Write-Log "Staging restore for probe '$($orig.Name)' to port $($orig.Port)" "INFO"
                Set-AzLoadBalancerProbeConfig -LoadBalancer $lb -Name $orig.Name -Protocol $orig.Protocol -Port $orig.Port -IntervalInSeconds $orig.IntervalInSeconds -ProbeCount $orig.ProbeCount -ErrorAction Stop
            }
            Write-Log "Updating Load Balancer '$LBName' to restore probes" "INFO"
            Set-AzLoadBalancer -LoadBalancer $lb -ErrorAction Stop | Out-Null
            Write-Log "Health probes for '$LBName' restored successfully" "SUCCESS"
            return [pscustomobject]@{ IsSuccess = $true; Status = 'Succeeded'; Message = $null }
        } catch {
            $errorMessage = "Failed to override health probes for LB '$LBName': $($_.Exception.Message)"
            Write-Log $errorMessage "ERROR"
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

Write-Verbose "===== Starting Load Balancer Health Probe Override ====="
$loggedSubscriptionToTargetZone = if ($null -eq $SubscriptionToTargetZone) { '<null>' } elseif ($SubscriptionToTargetZone -is [string]) { $SubscriptionToTargetZone } else { $SubscriptionToTargetZone | ConvertTo-Json -Compress -Depth 5 }
Write-Verbose "Raw Input: ResourceIds=$ResourceIds; SubscriptionToTargetZone=$loggedSubscriptionToTargetZone; TargetZone=$TargetZone"
$lbTargets = Get-ResourceTargets -ResourceIds $ResourceIds -SubscriptionToTargetZone $SubscriptionToTargetZone -TargetZone $TargetZone
Write-Verbose "Parsed $($lbTargets.Count) load balancer target(s)."

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

$scriptStart = Get-Date
$DurationTimeSpan = New-TimeSpan -Minutes $Duration

Write-Verbose "Starting parallel processing of $($lbTargets.Count) Load Balancers"

$functionsScript = $functions.ToString()

$resultsRaw = $lbTargets | ForEach-Object -Parallel {
    # Set VerbosePreference in the parallel runspace so Write-Verbose logs appear
    # Suppress engine-level module-load verbose noise (PowerShell emits "Loading module"
    # and "Importing cmdlet" while $VerbosePreference is Continue, regardless of -Verbose:$false).
    # Pre-import Az.Accounts silently, then enable verbose so our own Write-Verbose logs appear.
    $VerbosePreference = 'SilentlyContinue'
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Network -ErrorAction Stop
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
        $info = ConvertFrom-ResourceIdLB -ResourceId $rid

        # Authenticate and initialize modules in the parallel runspace, passing the target subscription
        Connect-ToAzure -ClientId $using:UAMIClientId -SubscriptionId $info.SubscriptionId | Out-Null
        Initialize-Modules | Out-Null

        $faultResult = Override-LoadBalancerHealthProbes -ResourceGroup $info.ResourceGroup -LBName $info.LBName -Duration $using:DurationTimeSpan -TargetZone $targetZone
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
    $resourceResults += @{ ResourceId=$r.ResourceId; IsSuccess=$r.IsSuccess; Error=$err; ProcessedAt=$processedAtUtc; ProcessingDurationMs=$durationMs; Metadata=@{ Status=$r.Status; DurationMinutes=$Duration } }
}

foreach ($unexpected in $unexpectedOutputs) {
    $details = ($unexpected | Out-String).Trim()
    $resourceResults += @{ ResourceId = $null; IsSuccess = $null; Error = @{ ErrorCode = 'UnexpectedOutput'; Message = if ($details) { $details } else { $unexpected.ToString() }; Details = $details; Category = $null; IsRetryable = $false }; ProcessedAt = (Get-Date).ToUniversalTime(); ProcessingDurationMs = 0; Metadata = @{ Status = $null; DurationMinutes=$Duration } }
}

$executionResult = [ordered]@{
    Status=$overallStatus
    ResourceResults=$resourceResults
    SuccessCount=$successCount
    FailureCount=$failureCount
    ExecutionStartTime=$scriptStart.ToUniversalTime()
    ExecutionEndTime=$scriptEnd.ToUniversalTime()
    GlobalError= if ($overallStatus -eq 'Failed') { 'All load balancer probe override operations failed.' } elseif ($overallStatus -eq 'PartialSuccess') { 'Some operations failed.' } else { $null }
}
$executionJson = $executionResult | ConvertTo-Json -Depth 6
Write-Output $executionJson

# Fail the runbook if any resource could not be faulted
if ($failureCount -gt 0) {
    $errorMsg = "Runbook failed: $failureCount out of $($lbTargets.Count) Load Balancer(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Verbose "All Load Balancer health probe override operations completed successfully."

#endregion