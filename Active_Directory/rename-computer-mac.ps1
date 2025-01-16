#!PS

$state       = "TX"
$prefix      = "ALLHYU"
$domain_user = "admin"
$domain_pass = "password"

<#
.SYNOPSIS
Renames computer using the format and reboots at midnight:
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

function rename_computer($name) {
    try { 
        $domain_joined = (Get-CimInstance win32_computersystem).PartOfDomain

        if ($domain_joined) { 
            $cred = [PsCredential]::New($user, ($pass | ConvertTo-SecureString -AsPlainText -Force))
            Rename-Computer -NewName $name -DomainCredential $cred -ErrorAction Stop 
        }
        else {
            $pass = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
            $user = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
            $null = net user /add $user $pass
            $null = net localgroup "administrators" /add $user
            $cred = [PsCredential]::New($user, ($pass | ConvertTo-SecureString -AsPlainText -Force))
            Rename-Computer -NewName $name -LocalCredential $cred -ErrorAction Stop
            $null = net user /delete $user
        }

        # Get tomorrow's date at midnight
        $midnight = (Get-Date).Date.AddDays(1)

        # Get the time difference between now and midnight
        $timeToMidnight = New-TimeSpan -Start (Get-Date) -End $midnight 

        # Get the total number of seconds 
        $secondsToMidnight = [Math]::Round($timeToMidnight.TotalSeconds)

        # Perform reboot
        shutdown -r -t $secondsToMidnight
    }
    catch {
        if (-not $domain_joined) { $null = net user /delete $user }
        Write-host "`nFailed to rename computer < $(hostname) > to < $name >`n$($Error[0])" -ForegroundColor yellow
    }
}

$newname = parse_nics(Get-NetAdapter)
rename_computer($newname)
