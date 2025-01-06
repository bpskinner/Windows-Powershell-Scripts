#!PS
$SSID         = "Example-Corp" # Case sensitive
$password     = ""
$SKIP_THESE   = "Example1_SSID","Example2_SSID" # If connected to these SSID's, do not run script.
$REMOVE_THESE = "Example-GUEST" # Removed AND Hides the network. This is a REGEX match, meaning anything you type will be matched against ANY possible matches.
$FORCE        = $true # force update/join to SSID regardless of hardwired/wifi status.
$HIDEALL      = $false # If true, hide ALL other SSID's except the one defined in $SSID


function change_SSID {
    $password = $password -replace "&","&amp;"
    $Current_SSID = (Get-CurrentWLAN).SSID
    
    if ($SKIP_THESE -contains $Current_SSID) { 
    
        Write-host "CONNECTED TO $($Current_SSID), SKIPPING!" 
    
    } else { 
        if (-not $FORCE) {
            $using_ETHERNET = $false
            $using_WIFI = $false

            Get-NetAdapter | Foreach-object {
                if ($_.Status -eq 'Up' -and $_.MediaType -match '802.3') { 
                    Write-host "CONNECTED VIA ETHERNET > SKIPPING"
                    Exit 
                }
            }

            if (-not $using_ETHERNET) {
                $WirelessAdapter = Get-NetAdapter | ? {
                    ($_.Status -eq 'Up' -and $_.MediaType -match '802.11' -and ($_.InterfaceDescription -match "Wi[\-]{0,1}Fi|Wireless" -or $_.Name -match "Wi[\-]{0,1}Fi|Wireless"))
                }
                
                if ($WirelessAdapter) { 
                    Write-host Wireless adapter found `"$($WirelessAdapter.Name) / $($WirelessAdapter.InterfaceDescription)`"
                    $using_WIFI = $true 
                }
            }
        }
        
        if ($FORCE) { 
            $WirelessAdapter = Get-NetAdapter | ? {
                ($_.InterfaceDescription -match "Wi[\-]{0,1}Fi|Wireless" -or $_.Name -match "Wi[\-]{0,1}Fi|Wireless")
            }
            if ($WirelessAdapter.count -gt 1) { $WirelessAdapter = $WirelessAdapter | ? {$_.Status -eq 'Up'} }
            Write-host Wireless adapter found `"$($WirelessAdapter.Name) / $($WirelessAdapter.InterfaceDescription)`"
            $using_WIFI = $true 
        }
    
        if ($Current_SSID -notmatch $SSID -and $using_WIFI -eq $true) {
            Write-host "Attempting connection to `"$SSID`""
    
            $hex = (Format-Hex -InputObject $SSID -Encoding ascii).ToString().replace('00000000','').replace($SSID,'').trim().replace(' ','')

            $currentprofiles=(((netsh.exe wlan show profiles) -match '\s{2,}:\s').split([Environment]::NewLine) | % {$_.split(':')[1].trim()}) | ? {$_ -notmatch $SSID}

            $xml_header = '<?xml version="1.0"?>
            <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
            '
            $xml_body = `
            "	<name>$($SSID)</name>
	            <SSIDConfig>
		            <SSID>
			            <hex>$($hex)</hex>
			            <name>$($SSID)</name>
		            </SSID>
	            </SSIDConfig>
	            <connectionType>ESS</connectionType>
	            <connectionMode>auto</connectionMode>
	            <MSM>
		            <security>
			            <authEncryption>
				            <authentication>WPA2PSK</authentication>
				            <encryption>AES</encryption>
				            <useOneX>false</useOneX>
			            </authEncryption>
			            <sharedKey>
				            <keyType>passPhrase</keyType>
				            <protected>false</protected>
				            <keyMaterial>$($password)</keyMaterial>
			            </sharedKey>
		            </security>
	            </MSM>
            "
            $xml_trailer =`
            '	<MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
		            <enableRandomization>false</enableRandomization>
	            </MacRandomization>
            </WLANProfile>'

            ($xml_header + $xml_body + $xml_trailer) > "c:\users\public\SSIDProfile.xml"

            Netsh WLAN add profile filename="c:\users\public\SSIDProfile.xml"
            sleep 3
            Netsh WLAN connect name="$($SSID)" interface="$($WirelessAdapter.Name)"
            Remove-item "c:\users\public\SSIDProfile.xml" -Force
        } else {
            Write-host "ALREADY CONNECTED TO > $SSID"
        }
    }
}

function cleanup_profiles {
	if ($REMOVE_THESE -eq $null) { return }
    $GuestProfiles=(((netsh.exe wlan show profiles) -match '\s{2,}:\s').split([Environment]::NewLine) | % {$_.split(':')[1].trim()}) | ? {$_ -imatch $REMOVE_THESE}
    $GuestProfiles
    $GuestProfiles | % { 
        Netsh wlan delete profile $_ 
        Netsh wlan add filter permission=block ssid="$_" networktype=infrastructure
    }
    if ($HIDEALL) {
        netsh wlan add filter permission=allow ssid="$SSID" networktype=infrastructure
        netsh wlan add filter permission=denyall networktype=infrastructure 
    }
    
    netsh wlan show filters
    
}

function Get-CurrentWLAN {

    # Get WLAN interface information
    $netshOutput = netsh wlan show interfaces
    $lines = $netshOutput -split "\r`n"`

    # Create an object to store WLAN information
    $CurrentInterface = New-Object PSObject

    # Parse and add interface details to the object
    foreach ($line in $lines) {
        $key, $value = $line -split ":\s+", 2

        if ($key -and $value -and ($key -notlike "*Hosted network status*")) {
            $CurrentInterface | Add-Member -MemberType NoteProperty -Force -Name $key.Trim() -Value $value.Trim()
        }
    }

    # Get WLAN profile information
    $WLANProfile = (netsh.exe wlan show profiles name="$($CurrentInterface.Profile)" key=clear | Select-String "Key Content" | Get-Unique)

    # Parse and add WLAN profile details to the object
    $key, $value = $WLANProfile -split ":\s+", 2

    if ($key -and $value) {
        $CurrentInterface | Add-Member -MemberType NoteProperty -Name $key.Trim() -Value $value.Trim()
    }

    # Return the object with WLAN information
    return $CurrentInterface
}

change_SSID
cleanup_profiles