# SYNOPSIS
#   Shuts down and recovers zoned node pools of an AKS cluster using Automation Account identity.
#
# DESCRIPTION
#   This runbook accepts an AKS cluster resource ID and a duration in minutes.
#   It authenticates via Managed Identity, identifies node pools pinned to any availability zone,
#   scales them to zero to simulate failure, waits for the specified duration, and then restores original counts.
#
# PARAMETERS
#   -ResourceId: The resource ID of the Azure Kubernetes Service cluster to target.
#   -DurationInMinutes: Time in minutes to wait before restoring node pool counts.
#
# EXAMPLE
#   .\Fault-AksZones.ps1 -ResourceId "/subscriptions/.../resourceGroups/myRG/providers/Microsoft.ContainerService/managedClusters/myAKS" -DurationInMinutes 15

#Requires -Modules Az.Aks
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Resource ID of the AKS cluster")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceId,

    [Parameter(Mandatory=$true, HelpMessage="Duration in minutes before restoring node pools")]
    [ValidateRange(1,1440)]
    [int]$DurationInMinutes
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
        Write-Log "Checking Az.Aks module..." "INFO"
        if (-not (Get-Module -Name Az.Aks -ListAvailable)) {
            Write-Log "Az.Aks module not available" "ERROR"
            return $false
        }
        if (-not (Get-Module -Name Az.Aks)) {
            Write-Log "Importing Az.Aks module..." "INFO"
            Import-Module Az.Aks -ErrorAction Stop
        }
        Write-Log "Az.Aks module ready" "SUCCESS"
        return $true
    } catch {
        Write-Log "Module initialization failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Shutdown and Recovery Logic
function Invoke-AksZoneFault {
    param(
        [string]$ResourceGroup,
        [string]$ClusterName,
        [int]$DurationInMinutes
    )
    try {
        Write-Log "Retrieving node pools for cluster '$ClusterName' in RG '$ResourceGroup'" "INFO"
        $nodePools = Get-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -ErrorAction Stop

        $zonedPools = $nodePools | Where-Object { $_.AvailabilityZones -and $_.AvailabilityZones.Count -gt 0 }
        if (-not $zonedPools) {
            Write-Log "No zoned node pools found. Nothing to fault." "WARNING"
            return $false
        }

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
            Update-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -Name $np.Name -Count 0 -ErrorAction Stop
        }

        Write-Log "Node pools shut down. Waiting $DurationInMinutes minutes before restore." "INFO"
        Start-Sleep -Seconds ($DurationInMinutes * 60)

        # Restore original counts and autoscale settings
        foreach ($name in $originalSettings.Keys) {
            $settings = $originalSettings[$name]

            Write-Log "Restoring node pool '$name' to $($settings.Count) nodes" "INFO"
            Update-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -Name $name -Count $settings.Count -ErrorAction Stop

            if ($settings.EnableAutoScaling -and $null -ne $settings.MinCount -and $null -ne $settings.MaxCount) {
                Write-Log "Re-enabling autoscale for node pool '$name' (Min: $($settings.MinCount), Max: $($settings.MaxCount))" "INFO"
                Update-AzAksNodePool -ResourceGroupName $ResourceGroup -ClusterName $ClusterName -Name $name `
                    -EnableAutoScaling:$true -MinCount $settings.MinCount -MaxCount $settings.MaxCount -ErrorAction Stop
            }
        }

        Write-Log "Node pools restored successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Error during AKS zone fault operation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Main
Write-Log "===== Starting AKS Zone Fault Injection =====" "INFO"
Write-Log "Target AKS: $ResourceId" "INFO"

if (-not (Connect-ToAzure)) { throw "Authentication failed" }
if (-not (Initialize-Modules)) { throw "Module init failed" }

# Parse input
$info = ConvertFrom-ResourceIdAKS -ResourceId $ResourceId
Write-Log "Parsed: Subscription=$($info.SubscriptionId), RG=$($info.ResourceGroup), Cluster=$($info.ClusterName)" "INFO"

# Switch subscription context
if ($info.SubscriptionId) {
    Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null
    Write-Log "Switched to subscription $($info.SubscriptionId)" "INFO"
}

# Invoke fault and recovery
$success = Invoke-AksZoneFault -ResourceGroup $info.ResourceGroup -ClusterName $info.ClusterName -DurationInMinutes $DurationInMinutes

if ($success) {
    Write-Log "AKS zone fault operation completed" "SUCCESS"
} else {
    Write-Log "AKS zone fault operation failed or no action taken" "ERROR"
    throw "AKS zone fault injection failed" }

Write-Log "===== Script execution finished =====" "INFO"
#endregion