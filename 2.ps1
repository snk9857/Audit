<# 
    NetworkAudit-Master.ps1
    Centralized Network Audit Script for AD Lab
    Checks:
      2.1 - Inbound restriction
      2.2 - Outbound restriction
      3.1 - DMZ creation
      3.2 - DMZ segmentation
      3.3 - Dual-homed devices
#>

[CmdletBinding()]
param(
  [string[]]$AllHosts = @('DC01','DC02','DC03','SRV02','SRV03'),
  [string[]]$InternalHosts = @('DC01','DC02','DC03'),
  [string[]]$DMZHosts = @('SRV02','SRV03'),
  [int[]]$PortsToCheck = @(3389,445,80,443,1433,5985,5986),
  [string]$OutputPath = ".\FullNetworkAudit-$(Get-Date -Format yyyyMMdd-HHmmss).json"
)

Write-Host "`n=== Running Network Audit on $($AllHosts.Count) Hosts ===`n" -ForegroundColor Cyan

function Get-HostAudit {
  [CmdletBinding()]
  param()

  $fwInbound = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
               Where-Object {$_.Action -eq 'Allow'}
  $fwOutbound = Get-NetFirewallRule -Direction Outbound -Enabled True -ErrorAction SilentlyContinue |
                Where-Object {$_.Action -eq 'Allow'}

  $allowAnyIn = $fwInbound | ForEach-Object {
    $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue).RemoteAddress
    if (-not $addr -or $addr -contains 'Any') { $_ }
  }

  $allowAnyOut = $fwOutbound | ForEach-Object {
    $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue).RemoteAddress
    if (-not $addr -or $addr -contains 'Any') { $_ }
  }

  $openPorts = (netstat -ano | Select-String -Pattern 'LISTENING') | ForEach-Object {
    $parts = ($_ -replace '\s+', ' ').Trim().Split(' ')
    if ($parts.Count -ge 5) {
      [pscustomobject]@{
        Protocol = $parts[0]
        Local    = $parts[1]
        Port     = [int]($parts[1].Split(':')[-1])
      }
    }
  }

  $nics = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object {$_.IPAddress -notmatch '^169\.254\.'}
  $dualHomed = ($nics | Select-Object -ExpandProperty InterfaceAlias -Unique).Count -gt 1

  [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = (Get-Date)
    InboundAllowAny = [bool]($allowAnyIn)
    OutboundAllowAny = [bool]($allowAnyOut)
    DualHomed = [bool]$dualHomed
    ListeningPorts = $openPorts
    NICs = $nics | Select-Object InterfaceAlias,IPAddress,PrefixLength
  }
}

# Run checks remotely
$results = foreach ($host in $AllHosts) {
  Write-Host "→ Auditing $host ..." -ForegroundColor Yellow
  try {
    Invoke-Command -ComputerName $host -ScriptBlock ${function:Get-HostAudit} -ErrorAction Stop
  }
  catch {
    [pscustomobject]@{
      ComputerName = $host
      Error = $_.Exception.Message
    }
  }
}

# ---- Segmentation Testing ----
Write-Host "`n=== Testing DMZ ↔ Internal Segmentation ===" -ForegroundColor Cyan
$segmentationResults = @()

foreach ($dmz in $DMZHosts) {
  foreach ($internal in $InternalHosts) {
    foreach ($p in $PortsToCheck) {
      $test = Test-NetConnection -ComputerName $internal -Port $p -WarningAction SilentlyContinue
      $segmentationResults += [pscustomobject]@{
        Source = $env:COMPUTERNAME
        Target = $internal
        Port = $p
        Reachable = $test.TcpTestSucceeded
      }
    }
  }
}

foreach ($internal in $InternalHosts) {
  foreach ($dmz in $DMZHosts) {
    foreach ($p in $PortsToCheck) {
      $test = Test-NetConnection -ComputerName $dmz -Port $p -WarningAction SilentlyContinue
      $segmentationResults += [pscustomobject]@{
        Source = $env:COMPUTERNAME
        Target = $dmz
        Port = $p
        Reachable = $test.TcpTestSucceeded
      }
    }
  }
}

# ---- Consolidated Summary ----
$summary = $results | Select-Object ComputerName,InboundAllowAny,OutboundAllowAny,DualHomed

Write-Host "`n=== SUMMARY ===`n" -ForegroundColor Green
$summary | Format-Table -AutoSize

$fullReport = [pscustomobject]@{
  CheckedAt = (Get-Date)
  HostResults = $results
  SegmentationTests = $segmentationResults
}

$fullReport | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $OutputPath
Write-Host "`n✅ Full audit saved to: $OutputPath" -ForegroundColor Cyan
