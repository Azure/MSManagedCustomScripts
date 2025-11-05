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
#   -ResourceId: The resource ID of the Azure Load Balancer to target.
#   -UAMIClientId: Optional. Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.
#
# EXAMPLE
#   .\Fault-LoadBalancerZones.ps1 -ResourceId "/subscriptions/xxx/.../loadBalancers/myLoadBalancer"
#   .\Fault-LoadBalancerZones.ps1 -ResourceId "/subscriptions/xxx/.../loadBalancers/myLoadBalancer" -UAMIClientId "12345678-1234-1234-1234-123456789012"

#Requires -Modules Az.Network, Az.Accounts
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Comma separated resource IDs of the Azure Load Balancers")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$true, HelpMessage="Duration in minutes to keep health probes down (e.g. '5' for 5 minutes)")]
    [ValidateNotNullOrEmpty()]
    [long]$Duration,

    [Parameter(Mandatory=$false, HelpMessage="Optional target availability zone to fault (e.g. '1'). Leave empty to fault all zones.")]
    [string]$TargetZone,

    [Parameter(Mandatory=$false, HelpMessage="Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.")]
    [string]$UAMIClientId
)

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
            "INFO"    { Write-Information $entry -InformationAction Continue }
            "WARNING" { Write-Warning $entry }
            "ERROR"   { Write-Error $entry }
            "SUCCESS" { Write-Information $entry -InformationAction Continue }
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
            [string]$ClientId
        )
        try {
            if ([string]::IsNullOrEmpty($ClientId)) {
                Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            } else {
                Write-Log "Authenticating to Azure via User-Assigned Managed Identity (ClientId: $ClientId)" "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -ErrorAction Stop | Out-Null
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
            if (-not (Get-Module -Name Az.Network -ListAvailable)) {
                throw "Az.Network module not available"
            }
            if (-not (Get-Module -Name Az.Network)) {
                Write-Log "Importing Az.Network module..." "INFO"
                Import-Module Az.Network -ErrorAction Stop
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
# Set InformationPreference to Continue to see Write-Information logs in automation job streams.
$InformationPreference = 'Continue'

Write-Information "===== Starting Load Balancer Health Probe Override ====="
Write-Information "Raw Input: $ResourceIds"
$lbIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $lbIds -or $lbIds.Count -eq 0) { throw "No valid load balancer resource IDs provided" }
Write-Information "Parsed $($lbIds.Count) load balancer id(s)."

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
$DurationTimeSpan = New-TimeSpan -Minutes $Duration

Write-Information "Starting parallel processing of $($lbIds.Count) Load Balancers"

$functionsScript = $functions.ToString()

$resultsRaw = $lbIds | ForEach-Object -Parallel {
    # Set InformationPreference in the parallel runspace so Write-Information logs appear
    $InformationPreference = 'Continue'
    
    # Define functions in the parallel runspace
    $functionBlock = [scriptblock]::Create($using:functionsScript)
    . $functionBlock

    $rid = $_
    $targetZoneValue = $null
    if ($using:TargetZone) {
        $targetZoneValue = ($using:TargetZone).Trim()
        if (-not $targetZoneValue) { $targetZoneValue = $null }
    }
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
        Initialize-Modules | Out-Null

        # Parse resource ID
        $info = ConvertFrom-ResourceIdLB -ResourceId $rid

        # Switch subscription context if needed
        $currentSub = (Get-AzContext).Subscription.Id
        if ($info.SubscriptionId -and $currentSub -ne $info.SubscriptionId) {
            Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null
            Write-Log "Switched to subscription $($info.SubscriptionId) for resource $rid" "INFO"
        }

        $faultResult = Override-LoadBalancerHealthProbes -ResourceGroup $info.ResourceGroup -LBName $info.LBName -Duration $using:DurationTimeSpan -TargetZone $targetZoneValue
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
    $errorMsg = "Runbook failed: $failureCount out of $($lbIds.Count) Load Balancer(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Information "All Load Balancer health probe override operations completed successfully." -InformationAction Continue

#endregion