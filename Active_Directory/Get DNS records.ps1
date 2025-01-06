
$servername = hostname
$serverip = (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -PrefixLength 24 -PrefixOrigin Manual)[0].IPAddress
$currentdomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select -ExpandProperty Domain
$prefix = $currentdomain.split(".")[0]
$suffix = $currentdomain.split(".")[1]
$fqdn = $($servername + "." + $prefix + "." + $suffix + ".")
$zonename = $($prefix + "." + $suffix)

$dnsrecords_msdcs = Get-DnsServerResourceRecord -ZoneName $(“_msdcs." + $zonename)
$dnsrecords = Get-DnsServerResourceRecord -ZoneName $zonename

$deadDC_msdcs = $dnsrecords_msdcs | Where-Object {$_.RecordData.IPv4Address -eq $serverip -or $_.RecordData.NameServer -eq $fqdn -or $_.RecordData.DomainName -eq $fqdn} 
$deadDC = $dnsrecords | Where-Object {$_.RecordData.IPv4Address -eq $serverip -or $_.RecordData.NameServer -eq $fqdn -or $_.RecordData.DomainName -eq $fqdn} 

$deadDC_msdcs | Remove-DnsServerResourceRecord -ZoneName $(“_msdcs." + $zonename + $suffix) -force -whatif
$deadDC | Remove-DnsServerResourceRecord -ZoneName $($zonename + $suffix) -force -whatif
