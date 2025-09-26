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

#Requires -Modules Az.Network
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Comma separated resource IDs of the Azure Load Balancers")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$true, HelpMessage="Duration in minutes to keep health probes down (e.g. '5' for 5 minutes)")]
    [ValidateNotNullOrEmpty()]
    [long]$Duration,

    [Parameter(Mandatory=$false, HelpMessage="Client ID of User-Assigned Managed Identity. If not provided, uses System-Assigned Managed Identity.")]
    [string]$UAMIClientId
)

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
        return $false
    }
}

function Initialize-Modules {
    try {
        Write-Log "Checking Az.Network module..." "INFO"
        if (-not (Get-Module -Name Az.Network -ListAvailable)) {
            Write-Log "Az.Network module not available" "ERROR"
            return $false
        }
        if (-not (Get-Module -Name Az.Network)) {
            Write-Log "Importing Az.Network module..." "INFO"
            Import-Module Az.Network -ErrorAction Stop
        }
        Write-Log "Az.Network module ready" "SUCCESS"
        return $true
    } catch {
        Write-Log "Module initialization failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Override Health Probes
function Override-LoadBalancerHealthProbes {
    param(
        [string]$ResourceGroup,
        [string]$LBName,
        [TimeSpan]$Duration
    )
    try {
        Write-Log "Retrieving Load Balancer '$LBName' in RG '$ResourceGroup'" "INFO"
        $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroup -Name $LBName -ErrorAction Stop

        # Identify probes to override
        $probesToOverride = @()
        foreach ($pool in $lb.BackendAddressPools) {
            foreach ($link in $pool.BackendIPConfigurations) {
                # Check if linked to zoned VM/VMSS
                $nic = Get-AzNetworkInterface -ResourceId $link.Id -ErrorAction SilentlyContinue
                if ($nic -and $nic.Zones) {
                    Write-Log "Found zoned backend NIC in pool '$($pool.Name)': zones=$($nic.Zones -join ',')" "INFO"
                    $probesToOverride += $lb.Probes | Where-Object { $_.Name -eq $pool.Probe.Name }
                }
            }
        }

        if (-not $probesToOverride) {
            Write-Log "No health probes found for zoned backends. Nothing to override." "WARNING"
            return $false
        }

        # Capture original probe settings before override
        $originalProbes = @()
        foreach ($probe in $probesToOverride | Select-Object -Unique) {
            $originalProbes += [PSCustomObject]@{
                Name               = $probe.Name
                Protocol           = $probe.Protocol
                Port               = $probe.Port
                IntervalInSeconds  = $probe.IntervalInSeconds
                ProbeCount         = $probe.ProbeCount
            }
        }

        # Override each probe by setting invalid port
        foreach ($probe in $probesToOverride | Select-Object -Unique) {
            Write-Log "Overriding probe '$($probe.Name)' (port $($probe.Port))->port 9999" "INFO"
            Set-AzLoadBalancerProbeConfig -LoadBalancer $lb -Name $probe.Name -Protocol $probe.Protocol -Port 9999 -IntervalInSeconds $probe.IntervalInSeconds -ProbeCount $probe.ProbeCount -ErrorAction Stop
        }

        # Commit changes
        Write-Log "Updating Load Balancer configuration" "INFO"
        Set-AzLoadBalancer -LoadBalancer $lb -ErrorAction Stop | Out-Null
        Write-Log "Health probes overridden successfully" "SUCCESS"

        # Wait for specified duration before restoring
        Write-Log "Sleeping for $Duration before re-enabling probes" "INFO"
        Start-Sleep -Seconds $Duration.TotalSeconds

        # Re-enable original health probes
        Write-Log "Re-enabling original health probes" "INFO"
        foreach ($orig in $originalProbes) {
            Write-Log "Restoring probe '$($orig.Name)'->port $($orig.Port)" "INFO"
            Set-AzLoadBalancerProbeConfig -LoadBalancer $lb -Name $orig.Name -Protocol $orig.Protocol -Port $orig.Port -IntervalInSeconds $orig.IntervalInSeconds -ProbeCount $orig.ProbeCount -ErrorAction Stop
        }
        Write-Log "Updating Load Balancer configuration to restore probes" "INFO"
        Set-AzLoadBalancer -LoadBalancer $lb -ErrorAction Stop | Out-Null
        Write-Log "Health probes re-enabled successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to override health probes: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Main
Write-Log "===== Starting Load Balancer Health Probe Override =====" "INFO"
Write-Log "Raw Input: $ResourceIds" "INFO"
$lbIds = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $lbIds -or $lbIds.Count -eq 0) { throw "No valid load balancer resource IDs provided" }
Write-Log "Parsed $($lbIds.Count) load balancer id(s)." 'INFO'

if (-not (Connect-ToAzure -ClientId $UAMIClientId)) { throw "Authentication failed" }
if (-not (Initialize-Modules)) { throw "Module init failed" }

$scriptStart = Get-Date
$results = @()
$DurationTimeSpan = New-TimeSpan -Minutes $Duration

# Capture function definitions for parallel execution
$functionDefs = @"
$(Get-Content Function:\Write-Log -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\ConvertFrom-ResourceIdLB -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Connect-ToAzure -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Initialize-Modules -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })

$(Get-Content Function:\Override-LoadBalancerHealthProbes -ErrorAction SilentlyContinue | ForEach-Object { $_.Definition })
"@

$results = $lbIds | ForEach-Object -Parallel {
    # Re-create function definitions in parallel runspace
    Invoke-Expression $using:functionDefs
    
    $rid = $_
    Write-Log "Processing LB: $rid" 'INFO'
    $parseErr = $null
    $info = $null
    $start = Get-Date
    try { $info = ConvertFrom-ResourceIdLB -ResourceId $rid } catch { $parseErr = $_.Exception.Message }
    if ($parseErr) {
        return [pscustomobject]@{ ResourceId=$rid; IsSuccess=$false; ErrorMessage=$parseErr; StartTime=$start; EndTime=$start; Status='FailedToStart' }
    }
    try {
        # Re-authenticate within parallel runspace
        if (-not (Connect-ToAzure -ClientId $using:UAMIClientId)) { 
            throw "Authentication failed in parallel runspace" 
        }
        if (-not (Initialize-Modules)) { 
            throw "Module initialization failed in parallel runspace" 
        }
        
        if ($info.SubscriptionId) { Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null }
        $success = Override-LoadBalancerHealthProbes -ResourceGroup $info.ResourceGroup -LBName $info.LBName -Duration $using:DurationTimeSpan
        $end = Get-Date
        return [pscustomobject]@{ ResourceId=$rid; IsSuccess=$success; ErrorMessage= if ($success) { $null } else { 'Override failed or no probes to override' }; StartTime=$start; EndTime=$end; Status= (if ($success) { 'Succeeded' } else { 'Failed' }) }
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
    $resourceResults += @{ ResourceId=$r.ResourceId; IsSuccess=$r.IsSuccess; Error=$err; ProcessedAt=$r.EndTime.ToUniversalTime(); ProcessingDurationMs=$durationMs; Metadata=@{ Status=$r.Status; DurationMinutes=$Duration } }
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
# Write-Log "Overall Status: $overallStatus (Success=$successCount Failure=$failureCount)" 'INFO'
# Write-Log "===== Script execution finished =====" "INFO"
#endregion