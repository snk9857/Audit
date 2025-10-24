<# 
    Audit-NetworkControls.ps1
    Checks:
      2.1 Inbound traffic restricted
      2.2 Outbound traffic restricted
      3.1 DMZ created via rules/subnets
      3.2 DMZ segmented from internal
      3.3 Dual-homed devices in DMZ

    Usage examples:
      .\Audit-NetworkControls.ps1 -ComputerName DC01,DC02,SRV02,SRV03 `
        -InternalSubnets '192.168.56.0/24' -DMZSubnets '192.168.57.0/24' `
        -DMZHosts SRV02,SRV03 -InternalHosts DC01,DC02

#>

[CmdletBinding()]
param(
  [string[]]$ComputerName = $env:COMPUTERNAME,
  [string[]]$InternalSubnets,
  [string[]]$DMZSubnets,
  [string[]]$InternalHosts,
  [string[]]$DMZHosts,
  [int[]]   $PortsToCheck = @(3389,445,80,443,1433,5985,5986),
  [string]  $OutputPath = ".\Audit-NetworkControls-$(Get-Date -Format yyyyMMdd-HHmmss).json"
)

function Invoke-On {
  param([string]$Computer,[scriptblock]$Script)
  if ($Computer -ieq $env:COMPUTERNAME) { & $Script } else {
    Invoke-Command -ComputerName $Computer -ScriptBlock $Script -ErrorAction SilentlyContinue
  }
}

function Get-FirewallSummary {
  # Returns inbound/outbound allow rules + obvious "allow any" indicators
  $in = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
        Where-Object {$_.Action -eq 'Allow'}
  $out = Get-NetFirewallRule -Direction Outbound -Enabled True -ErrorAction SilentlyContinue |
         Where-Object {$_.Action -eq 'Allow'}

  $inDetails = foreach($r in $in){
    $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
    $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
    [pscustomobject]@{
      RuleName   = $r.DisplayName
      Profiles   = $r.Profile
      Ports      = ($pf.LocalPort -join ',')
      Protocol   = $pf.Protocol
      RemoteAddr = if($af.RemoteAddress){$af.RemoteAddress -join ','} else {'Any'}
      Service    = $r.Service
      Program    = $r.Program
    }
  }

  $outDetails = foreach($r in $out){
    $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
    $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
    [pscustomobject]@{
      RuleName   = $r.DisplayName
      Profiles   = $r.Profile
      Ports      = ($pf.RemotePort -join ',')
      Protocol   = $pf.Protocol
      RemoteAddr = if($af.RemoteAddress){$af.RemoteAddress -join ','} else {'Any'}
      Service    = $r.Service
      Program    = $r.Program
    }
  }

  # Simple heuristics for risk flags
  $inAllowAny =
    $inDetails | Where-Object { $_.RemoteAddr -eq 'Any' -and ($_.Ports -eq '' -or $_.Ports -match 'Any') }
  $outAllowAny =
    $outDetails | Where-Object { $_.RemoteAddr -eq 'Any' -and ($_.Ports -eq '' -or $_.Ports -match 'Any') }

  [pscustomobject]@{
    InboundRules  = $inDetails
    OutboundRules = $outDetails
    Inbound_AllowAnyIndicator  = [bool]($inAllowAny)
    Outbound_AllowAnyIndicator = [bool]($outAllowAny)
  }
}

function Get-OpenPorts {
  # Uses netstat to inventory listening ports
  $raw = netstat -ano | Select-String -Pattern 'LISTENING'
  foreach($line in $raw){
    $parts = ($line -replace '\s+', ' ').Trim().Split(' ')
    if($parts.Count -ge 5){
      $local = $parts[1]
      $proto = $parts[0]
      $pid   = $parts[-1]
      $port  = [int]($local.Split(':')[-1] -replace '\[|\]','')
      [pscustomobject]@{
        Protocol = $proto
        Local    = $local
        Port     = $port
        PID      = $pid
        Process  = (Get-Process -Id $pid -ErrorAction SilentlyContinue).ProcessName
      }
    }
  }
}

function Test-PortsFromHere {
  param([string[]]$Targets,[int[]]$Ports)
  $out = foreach($t in $Targets){
    foreach($p in $Ports){
      $r = Test-NetConnection -ComputerName $t -Port $p -WarningAction SilentlyContinue
      [pscustomobject]@{
        Target = $t; Port=$p; Reachable=$r.TcpTestSucceeded; RemoteAddress=$r.RemoteAddress
      }
    }
  }
  $out
}

function Get-NICLayout {
  # NIC/IP/Subnet info + dual-homed flag
  $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {$_.IPAddress -notmatch '^169\.254\.'}
  $nic = foreach($i in $ip){
    [pscustomobject]@{
      InterfaceAlias = $i.InterfaceAlias
      IPAddress      = $i.IPAddress
      PrefixLength   = $i.PrefixLength
      Subnet         = "$($i.IPAddress)/$($i.PrefixLength)"
    }
  }
  $dualHomed = ($nic | Select-Object -ExpandProperty InterfaceAlias -Unique).Count -gt 1 -and
               ($nic.Count -gt 1)
  [pscustomobject]@{
    Interfaces = $nic
    DualHomedIndicator = [bool]$dualHomed
  }
}

function Test-Segmentation {
  param(
    [string[]]$FromDMZToInternalTargets,
    [string[]]$FromInternalToDMZTargets,
    [int[]]$Ports
  )
  [pscustomobject]@{
    DMZ_to_Internal  = if($FromDMZToInternalTargets){ Test-PortsFromHere -Targets $FromDMZToInternalTargets -Ports $Ports }
    Internal_to_DMZ  = if($FromInternalToDMZTargets){ Test-PortsFromHere -Targets $FromInternalToDMZTargets -Ports $Ports }
  }
}

# -------- MAIN --------
$report = @()

foreach($c in $ComputerName){
  try {
    $result = Invoke-On -Computer $c -Script {
      $fw = Get-FirewallSummary
      $ports = Get-OpenPorts
      $nics = Get-NICLayout
      [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Timestamp    = (Get-Date)
        Firewall     = $fw
        ListeningPorts = $ports
        NICLayout    = $nics
      }
    }

    # Optional segmentation tests (run FROM EACH machine if you pass targets)
    $seg = $null
    if($DMZHosts -and $InternalHosts){
      $isDMZ = $false
      if ($DMZHosts -contains $c) { $isDMZ = $true }
      $seg = if($isDMZ){
        Test-Segmentation -FromDMZToInternalTargets $InternalHosts -Ports $PortsToCheck
      } else {
        Test-Segmentation -FromInternalToDMZTargets $DMZHosts -Ports $PortsToCheck
      }
    }

    # Simple PASS/FAIL heuristics mapped to 2.x/3.x
    $inOk  = -not $result.Firewall.Inbound_AllowAnyIndicator
    $outOk = -not $result.Firewall.Outbound_AllowAnyIndicator
    $dualHomed = $result.NICLayout.DualHomedIndicator

    $report += [pscustomobject]@{
      ComputerName = $c
      CheckedAt    = (Get-Date)
      "2.1_InboundRestricted_PASS"  = $inOk
      "2.2_OutboundRestricted_PASS" = $outOk
      "3.1_DMZCreated_HINT"         = @($InternalSubnets + $DMZSubnets) -ne $null
      "3.2_Segmentation_Results"    = $seg
      "3.3_DualHomedIndicator"      = $dualHomed
      FirewallInboundRules          = $result.Firewall.InboundRules
      FirewallOutboundRules         = $result.Firewall.OutboundRules
      ListeningPorts                = $result.ListeningPorts
      NICs                          = $result.NICLayout.Interfaces
    }
  } catch {
    $report += [pscustomobject]@{ ComputerName=$c; Error=$_.Exception.Message }
  }
}

# Output to screen (brief) and save full JSON
$report |
  Select-Object ComputerName, '2.1_InboundRestricted_PASS', '2.2_OutboundRestricted_PASS',
                '3.1_DMZCreated_HINT','3.3_DualHomedIndicator' |
  Format-Table -AutoSize

$report | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $OutputPath
Write-Host "`nFull report saved to: $OutputPath"
