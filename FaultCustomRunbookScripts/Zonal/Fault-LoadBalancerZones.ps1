# SYNOPSIS
#   Performs fault injection by overriding health probes on an Azure Load Balancer using Automation Account identity.
#
# DESCRIPTION
#   This runbook accepts a Load Balancer resource ID and uses Managed Identity to authenticate.
#   It locates all health probes associated with backend pools that have VMs or VMSS instances pinned to any availability zone,
#   and overrides their settings to simulate failure (e.g., by changing probe port to an invalid port).
#   This helps test zone resiliency by forcing traffic away from zoned backends.
#
# PARAMETERS
#   -ResourceId: The resource ID of the Azure Load Balancer to target.
#
# EXAMPLE
#   .\Fault-LoadBalancerZones.ps1 -ResourceId "/subscriptions/xxx/.../loadBalancers/myLoadBalancer"

#Requires -Modules Az.Network
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Resource ID of the Azure Load Balancer")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceId,

    [Parameter(Mandatory=$true, HelpMessage="Duration to keep health probes down (TimeSpan, e.g. '00:05:00' for 5 minutes)")]
    [ValidateNotNullOrEmpty()]
    [TimeSpan]$Duration
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
        "INFO"    { Write-Output $entry }
        "WARNING" { Write-Warning $entry }
        "ERROR"   { Write-Error $entry }
        "SUCCESS" { Write-Output $entry }
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
    try {
        Write-Log "Authenticating to Azure via Managed Identity" "INFO"
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
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
Write-Log "Target LB: $ResourceId" "INFO"

if (-not (Connect-ToAzure)) { throw "Authentication failed" }
if (-not (Initialize-Modules)) { throw "Module init failed" }

# Parse input
$info = ConvertFrom-ResourceIdLB -ResourceId $ResourceId
Write-Log "Parsed: Subscription=$($info.SubscriptionId), RG=$($info.ResourceGroup), LB=$($info.LBName)" "INFO"

# Switch subscription context
if ($info.SubscriptionId) {
    Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null
    Write-Log "Switched to subscription $($info.SubscriptionId)" "INFO"
}

# Perform override
$success = Override-LoadBalancerHealthProbes -ResourceGroup $info.ResourceGroup -LBName $info.LBName -Duration $Duration

if ($success) {
    Write-Log "Override operation completed" "SUCCESS"
} else {
    Write-Log "Override operation did not make changes or failed" "ERROR"
    throw "Health probe override failed or no probes to override"
}
Write-Log "===== Script execution finished =====" "INFO"
#endregion