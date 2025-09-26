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
#   -ResourceIds: Comma separated list of AKS cluster resource IDs.
#   -DurationInMinutes: Time in minutes to wait before restoring node pool counts.
#
# EXAMPLE
#   .\Fault-AksZones.ps1 -ResourceId "/subscriptions/.../resourceGroups/myRG/providers/Microsoft.ContainerService/managedClusters/myAKS" -DurationInMinutes 15

#Requires -Modules Az.Aks
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Comma separated AKS cluster resource IDs")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$true, HelpMessage="Duration in minutes before restoring node pools")]
    [ValidateRange(1,1440)]
    [int]$DurationInMinutes,

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
        [string]$ClientId
    )
    try 
    {
        if ([string]::IsNullOrEmpty($ClientId)) 
        {
            Write-Log "Authenticating to Azure via System-Assigned Managed Identity" "INFO"
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        } 
        else 
        {
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
Write-Log "Target AKS Raw Input: $ResourceIds" "INFO"

$AksResourceList = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $AksResourceList -or $AksResourceList.Count -eq 0) { throw "No valid AKS resource IDs provided" }
Write-Log "Parsed $($AksResourceList.Count) AKS resource id(s)." 'INFO'

$scriptStart = Get-Date
$operationObjects = @()

if (-not (Connect-ToAzure -ClientId $UAMIClientId)) { throw "Authentication failed" }
if (-not (Initialize-Modules)) { throw "Module init failed" }

# Capture function definitions for parallel execution
$functionDefs = @(
    (Get-Command Write-Log).ScriptBlock.ToString(),
    (Get-Command ConvertFrom-ResourceIdAKS).ScriptBlock.ToString(),
    (Get-Command Connect-ToAzure).ScriptBlock.ToString(),
    (Get-Command Initialize-Modules).ScriptBlock.ToString(),
    (Get-Command Invoke-AksZoneFault).ScriptBlock.ToString()
) -join "`n`n"

Write-Log "Starting parallel processing of $($AksResourceList.Count) AKS clusters" "INFO"

$operationObjects = $AksResourceList | ForEach-Object -Parallel {
    param($rid, $durationMinutes, $uamiClientId, $funcs)
    
    # Re-create functions in parallel runspace
    Invoke-Expression $funcs
    
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
        # Parse resource ID
        $info = ConvertFrom-ResourceIdAKS -ResourceId $rid
        
        # Authenticate in parallel runspace
        if (-not (Connect-ToAzure -ClientId $uamiClientId)) {
            throw "Authentication failed in parallel runspace"
        }
        
        # Initialize modules in parallel runspace
        if (-not (Initialize-Modules)) {
            throw "Module initialization failed in parallel runspace"
        }
        
        # Switch subscription context if needed
        if ($info.SubscriptionId) { 
            Set-AzContext -SubscriptionId $info.SubscriptionId -ErrorAction Stop | Out-Null 
        }
        
        # Execute the fault operation
        $success = Invoke-AksZoneFault -ResourceGroup $info.ResourceGroup -ClusterName $info.ClusterName -DurationInMinutes $durationMinutes
        $end = Get-Date
        
        $result.IsSuccess = $success
        $result.ErrorMessage = if ($success) { $null } else { 'Operation failed or no zoned pools' }
        $result.EndTime = $end
        $result.Status = if ($success) { 'Succeeded' } else { 'Failed' }
        
    } catch {
        $result.EndTime = Get-Date
        $result.ErrorMessage = $_.Exception.Message
        $result.Status = 'Failed'
    }
    
    return $result
} -ArgumentList $DurationInMinutes, $UAMIClientId, $functionDefs

$scriptEnd = Get-Date
$successCount = ($operationObjects | Where-Object { $_.IsSuccess }).Count
$failureCount = ($operationObjects | Where-Object { -not $_.IsSuccess }).Count
$overallStatus = if ($failureCount -eq 0) { 'Success' } elseif ($successCount -gt 0) { 'PartialSuccess' } else { 'Failed' }

$resourceResults = @()
foreach ($op in $operationObjects) {
    $durationMs = [int]([Math]::Round((($op.EndTime) - $op.StartTime).TotalMilliseconds))
    $err = $null
    if (-not $op.IsSuccess) {
        $err = @{ ErrorCode='FailedToFaultResource'; Message=$op.ErrorMessage; Details=$op.ErrorMessage; Category=$op.Status; IsRetryable=$false }
    }
    $resourceResults += @{ ResourceId=$op.ResourceId; IsSuccess=$op.IsSuccess; Error=$err; ProcessedAt=$op.EndTime.ToUniversalTime(); ProcessingDurationMs=$durationMs; Metadata=@{ Status=$op.Status } }
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
# Write-Log "Overall Status: $overallStatus (Success=$successCount Failure=$failureCount)" 'INFO'
# Write-Log "===== AKS Zone Fault Injection Finished =====" 'INFO'
#endregion