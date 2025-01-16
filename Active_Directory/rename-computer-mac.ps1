#!PS

$state       = "TX"
$prefix      = "ALLHYU"
$domain_user = "admin"
$domain_pass = "password"

<#
.SYNOPSIS
Renames computer using the format:
      "TXALLHYU-8B5D51"
       |   |      |
      /    |       \
     |     |        |
   "StateStore-MacAddress"
 [2 Chars][6 to 7 Chars]-[6 Chars]

 State must equal 2      characters
 Store must equal 6 to 7 characters
 Dash  must equal 1      characters
 Mac   must equal 5 to 6 characters 

.DESCRIPTION
Please fill out the state and prefix using the correct information provided by the corporate team.
Do not modify any other parameters of the script while running.
Additionally, please verify that ANY computer you run scripts on are not hosting any services. I.e. Servers, Matrix/Oil machines...
The length of the Mac Address chosen will be automatically determined using the length of the store prefix. 

.NOTES
01/16/2025
#>

$u = $domain_user
$p = $domain_pass | ConvertTo-SecureString -AsPlainText -Force
$dcred = [PsCredential]::New($u, $p)

function parse_name ($nic) { 
    $parsed_mac = ($nic.MacAddress.replace("-","")[($prefix.Length)..12] -join '')
    $_ = "$($state)$($prefix)-$($parsed_mac)"
    
    Write-host "Adapter found -> $($nic.Name) 
              `nDescription   -> $($nic.InterfaceDescription) 
              `nAddress       -> $($nic.MacAddress) ($parsed_mac)
              `nUpdated Name  -> $_"

    return $_
}

function parse_nics ($net_interfaces) {
    
    $net_interfaces | % {
        if (
            $_.Status -eq 'Up' `
            -and $_.MediaType -match '802.3' `
            -and $_.Virtual -eq $false
        ) { 
            return parse_name($_)
        }
    }
    
    $net_interfaces | % {
        if (
            $_.Status -eq 'Up' `
            -and $_.MediaType -match '802.11' `
            -and ($_.InterfaceDescription -match "Wi[\-]{0,1}Fi|Wireless" -or $_.Name -match "Wi[\-]{0,1}Fi|Wireless")
        ) {
            return parse_name($_)
        }
    }
    
}

$name = parse_nics(Get-NetAdapter)

try { 
    Rename-Computer -NewName $name -DomainCredential $dcred -ErrorAction Stop

    # Get tomorrow's date at midnight
    $midnight = (Get-Date).Date.AddDays(1)

    # Get the time difference between now and midnight
    $timeToMidnight = New-TimeSpan -Start (Get-Date) -End $midnight 

    # Get the total number of seconds 
    $secondsToMidnight = [Math]::Round($timeToMidnight.TotalSeconds)

    # Output the result
    shutdown -r -t $secondsToMidnight
}
catch {
    Write-host "`nFailed to rename computer < $(hostname) > to < $name > n$($Error[0])" -ForegroundColor yellow
}