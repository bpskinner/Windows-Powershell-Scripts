#!PS
# // SSID's are Case sensitive // 
# // Please carefully fill out the options below //
$SSID             = "MRNISSATL-Corp" 
$password         = "***"
$SKIP_THESE       = "Example1_SSID","Example2_SSID" # If connected to these SSID's, do not run script.
$REMOVE_THESE     = "MRNISSATL-Employee","MRNISSATL-CORP","MRNISSATL-Tablet","MRNISSATL-Vendor","MRNISSATL-Tech","MRNISSATL-Employee-PD","Nissan PREMIUM Guest-WiFi","MRNISSATL-PScan" # Removed AND Hides the network. This is a REGEX match, meaning anything you type will be matched against ANY possible matches.
$FORCE_CONNECTION = $false # force update/join to SSID regardless of hardwired/wifi status.
$ADD_PROFILE      = $true  # Adds new SSID profile no matter what.
$CONNECT_TO_SSID  = $false # whether or not to actually attempt to connect
$HIDE_ALL          = $false # If true, hide ALL other SSID's except the one defined in $SSID.

restart-service wlansvc

function change_SSID {
    $password = $password -replace "&","&amp;"
    $Current_SSID = (Get-CurrentWLAN).SSID
    
    if ($SKIP_THESE -contains $Current_SSID) { 
    
        Write-host "CONNECTED TO $($Current_SSID), skipping!" 
    
    } else { 
        if (-not $FORCE_CONNECTION) {
            $using_ETHERNET = $false
            $using_WIFI = $false

            Get-NetAdapter | Foreach-object {
                if ($_.Status -eq 'Up' -and $_.MediaType -match '802.3') { 
                    Write-host "CONNECTED VIA ETHERNET!`n"
                    $using_ETHERNET = $true
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
        
        if ($FORCE_CONNECTION) { 
            $WirelessAdapter = Get-NetAdapter | ? {
                ($_.InterfaceDescription -match "Wi[\-]{0,1}Fi|Wireless" -or $_.Name -match "Wi[\-]{0,1}Fi|Wireless")
            }
            if ($WirelessAdapter.count -gt 1) { $WirelessAdapter = $WirelessAdapter | ? {$_.Status -eq 'Up'} }
            Write-host Wireless adapter found `"$($WirelessAdapter.Name) / $($WirelessAdapter.InterfaceDescription)`"
            $using_WIFI = $true 
        }
        
		$connected = $Current_SSID -eq $SSID 
            
		if ($ADD_PROFILE -or $connected -eq $false) {
			$hex = (Format-Hex -InputObject $SSID -Encoding ascii).ToString().replace('00000000','').replace($SSID,'').trim().replace(' ','')

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
		}
		
		
		if ($connected) { Write-host "ALREADY CONNECTED TO $SSID!" }
        if ($connected -eq $false -and $using_WIFI -eq $true -and $CONNECT_TO_SSID) {
			Write-host "Attempting connection to `"$SSID`""
            Netsh WLAN connect name="$($SSID)" interface="$($WirelessAdapter.Name)"
            Remove-item "c:\users\public\SSIDProfile.xml" -Force
        }
    }
}

function cleanup_profiles {
	if ($REMOVE_THESE -eq $null) { exit }
	
	$Profiles = (netsh.exe wlan show profiles) -match '\s:\s'
	
	if ($Profiles) {
		
		$WirelessAdapter = Get-NetAdapter | ? {
			$_.MediaType -match '802.11'
		}
		$WiFiGuid = $WirelessAdapter | Select-Object -ExpandProperty InterfaceGUID
		$Path = "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\$WiFiGuid"
		$ProfilePaths = Get-ChildItem $Path | Select-Object -ExpandProperty FullName
		$ProfilesMarked = $ProfilePaths | % {
			[xml]$WiFiProfile = Get-Content $_
			$ProfileName = $WiFiProfile.WLANProfile.name
			
			if ($ProfileName -cin $REMOVE_THESE) { 
				$_
			}
		}
		if ($ProfilesMarked) {
			Write-host `nDeleting the following SSID profiles:
			$ProfilesMarked  | % {
				$ProfileName = [XML](Get-Content $_)
				Write-host "    > Deleted $($ProfileName.WLANProfile.name)!"
				Remove-Item $_ -Force
			}
			restart-service wlansvc
		}
	}
	
    if ($HIDE_ALL) {
        netsh wlan add filter permission=allow ssid="$SSID" networktype=infrastructure
        netsh wlan add filter permission=denyall networktype=infrastructure 
    }
	else {
		$REMOVE_THESE | % {
			$null = Netsh wlan add filter permission=block ssid="$_" networktype=infrastructure
		}
	}
    
	Write-host `nSuccessfully Blocked SSIDs:
    ( (netsh wlan show filters) -join "`n" -split "-------------------------------")[-1]
    
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

Write-host Successfully Configured SSIDs:
( (netsh wlan show profiles) -join "`n" -split "-------------")[-1]
