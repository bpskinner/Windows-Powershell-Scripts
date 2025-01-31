#!PS
## Get the Physical NIC
$adapter = Get-NetAdapter -Physical

## Get the NIC Name as a System Variable
$nicName = $Adapter.Name

## Get the NIC Index
$nicIndex = $adapter.ifIndex

## Set the network interface to a variable for future use
$interface = Get-NetIPInterface -InterfaceIndex $nicIndex -AddressFamily IPv4

## Remove the static default gateway
Remove-NetRoute -InterfaceIndex $nicIndex -AddressFamily IPv4 -Confirm:$false

## Set interface to "Obtain an IP address automatically"
Set-NetIPInterface -InterfaceIndex $nicIndex -Dhcp Enabled

## Set interface to "Obtain DNS server address automatically"
$interface | Set-DnsClientServerAddress -ResetServerAddresses

## Sleep to allow some environments to process (older hardware)
Start-Sleep -Seconds 10

## Restart the NIC for Sanity
Restart-NetAdapter -Name $nicName -Confirm:$false -Verbose

## Sleep to allow some environments to process (older hardware)
Start-Sleep -Seconds 10

## Display new IP 
### (nice for me as I utilize this information but not needed)
$NewIP = (Get-NetIPAddress -InterfaceIndex $nicIndex).IPv4Address
$NewIP

## Register the adapter in DNS
Register-DnsClient -Verbose

## Flush the DNS cache
Clear-DnsClientCache -Verbose



#!PS
# Reconfigure STATIC gateway

## Get the NIC Index
#$nicIndex = (get-netroute | ? {$_.NextHop -eq '10.226.138.254'}).ifIndex
#if ($nicIndex -ne $null) {
#    New-NetRoute -DestinationPrefix 0.0.0.0/0 -NextHop 10.226.138.224 -InterfaceIndex $nicIndex -AddressFamily IPv4 -RouteMetric 1 -Verbose
#    Sleep 15
#    if ([Boolean](Test-Connection -IPAddress '1.1.1.1' -Count 3 -ErrorAction SilentlyContinue)) {
#        Remove-NetRoute -InterfaceIndex $nicIndex -NextHop '10.226.138.254' -Confirm:$false -Verbose
#        }
#    }
