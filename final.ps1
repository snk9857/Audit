Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
ForEach-Object {
    $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_
    $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_
    [pscustomobject]@{
        Rule          = $_.DisplayName
        Protocol      = $pf.Protocol
        LocalPort     = ($pf.LocalPort -join ',')
        RemoteAddress = ($af.RemoteAddress -join ',')
        Profile       = $_.Profile
    }
} | Format-Table -AutoSize
