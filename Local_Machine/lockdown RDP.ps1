$rules = @("Remote Desktop - User Mode (TCP-In)", "Remote Desktop - User Mode (UDP-In)")
$DNS = (get-dnsclientserveraddress | ? { $_.serveraddresses -match '172.[\d]{1,3}.[\d]{1,3}.[\d]{1,3}' -or $_.serveraddresses -match '10.[\d]{1,3}.[\d]{1,3}.[\d]{1,3}' -or $_.serveraddresses -match '192.168.[\d]{1,3}.[\d]{1,3}'}).serveraddresses
$subnets = @("10.12.18.0/24","10.0.24.0/24")
$subnets += $DNS
Foreach ($rule in $rules) { 
    Get-NetFirewallrule -DisplayName $rule | `
        Get-NetFirewallAddressFilter | `
        Set-NetFirewallAddressFilter -RemoteAddress $subnets 
    }


$int = (Get-NetAdapter).name
$int | % { Set-NetIPInterface -InterfaceAlias $_ -Dhcp Enabled -AddressFamily IPv4 -WhatIf }
