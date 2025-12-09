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

#Requires -Modules Az.Aks, Az.Accounts
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Comma separated AKS cluster resource IDs")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceIds,

    [Parameter(Mandatory=$true, HelpMessage="Duration in minutes before restoring node pools")]
    [ValidateRange(1,1440)]
    [Alias("DurationInMinutes")]
    [int]$Duration,

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
                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            }
            else
            {
                Write-Log "Authenticating to Azure via User-Assigned Managed Identity (ClientId: $ClientId)" "INFO"
                Connect-AzAccount -Identity -AccountId $ClientId -ErrorAction Stop | Out-Null
            }

            # If a subscription ID is provided, set the context to that subscription immediately
            if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
                Write-Log "Setting subscription context to $SubscriptionId" "INFO"
                Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
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
            if (-not (Get-Module -Name Az.Aks -ListAvailable)) {
                throw "Az.Aks module not available"
            }
            if (-not (Get-Module -Name Az.Aks)) {
                Write-Log "Importing Az.Aks module..." "INFO"
                Import-Module Az.Aks -ErrorAction Stop
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
$VerbosePreference = 'Continue'

Write-Verbose "===== Starting AKS Zone Fault Injection ====="
Write-Verbose "Target AKS Raw Input: $ResourceIds"

$AksResourceList = $ResourceIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $AksResourceList -or $AksResourceList.Count -eq 0) { throw "No valid AKS resource IDs provided" }
Write-Verbose "Parsed $($AksResourceList.Count) AKS resource id(s)."

$scriptStart = Get-Date
$operationObjects = @()

# Initial connection check in main thread
try {
    if ($UAMIClientId) {
        Connect-AzAccount -Identity -AccountId $UAMIClientId -ErrorAction Stop | Out-Null
    } else {
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    }
    $ctx = Get-AzContext -ErrorAction Stop
    Write-Verbose "Initial connection successful as $($ctx.Account.Id) on subscription $($ctx.Subscription.Name)"
} catch {
    throw "Initial Azure authentication failed. Please check Managed Identity configuration. Error: $($_.Exception.Message)"
}

Write-Verbose "Starting parallel processing of $($AksResourceList.Count) AKS clusters"

$functionsScript = $functions.ToString()

$operationObjectsRaw = $AksResourceList | ForEach-Object -Parallel {
    # Set VerbosePreference in the parallel runspace so Write-Verbose logs appear
    $VerbosePreference = 'Continue'
    
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
        # Parse resource ID first to get the subscription
        $info = ConvertFrom-ResourceIdAKS -ResourceId $rid

        # Authenticate and initialize modules in the parallel runspace, passing the target subscription
        Connect-ToAzure -ClientId $using:UAMIClientId -SubscriptionId $info.SubscriptionId | Out-Null
        Initialize-Modules | Out-Null

        # Execute the fault operation
        $faultResult = Invoke-AksZoneFault -ResourceGroup $info.ResourceGroup -ClusterName $info.ClusterName -DurationInMinutes $using:Duration
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
    $errorMsg = "Runbook failed: $failureCount out of $($AksResourceList.Count) AKS cluster(s) could not be faulted. Status: $overallStatus"
    Write-Error $errorMsg -ErrorAction Stop
    throw $errorMsg
}

Write-Verbose "All AKS zone fault operations completed successfully."

#endregion