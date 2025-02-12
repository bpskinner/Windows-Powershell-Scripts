#!PS

# SSID's are Case sensitive.
# Please carefully fill out the options below. Set everything to false if you only want to block/unblock SSIDs.
$NEW_SSID = "MFFL-Corp" 
$PASSWORD = "***"

# Set to true if SSID uses WPA3 else use WPA2.
# Will be overridden by network scan if the scan determines a different WPA method in use.
$USE_WPA3 = $false

# Adds the new SSID profile only only if the device IS wireless.
$ADD_PROFILE = $true  

# Sets the new SSID profile mode to autoconnect. 
# This can be used to allow Windows to attempt the connection automatically, but also relies on Windows to fail back to the previous SSID if something goes wrong.
$PROFILE_AUTOCONNECT = $false

# Connect to the new SSID only if the device IS NOT hardwired.
# Requires $ADD_PROFILE/$FORCE_ADD_PROFILE to be true.
$CONNECT_TO_SSID = $true

# Adds the new SSID profile regardless of hardwired/wireless status.
$FORCE_ADD_PROFILE = $true

# Force the device to connect to the new SSID regardless of hardwired/wireless status.
# Also overrides $CONNECT_TO_SSID and $ADD_PROFILE/$FORCE_ADD_PROFILE.
$FORCE_CONNECT = $true

# If device is connected to any of these SSID's, cancel script.
$SKIP_THESE = "Example1_SSID","Example2_SSID" 

# Removes SSID if it's saved and hides the network so the device can't try to connect.
# Overrides $UNBLOCK_THESE.
$BLOCK_THESE = "MFFL-Employee-PD","MFFL-Tablets","MFFL-Vendor","MFFL-Tech","MFFL-Guest-WiFi"

# Whether or not to block all SSIDs even if the device is currently connected to one of them.
# Use this for computers that are hardwired but also connected to an SSID you want to block.
$FORCE_BLOCK = $false

# Unblocks SSID if it's already been hidden. 
$UNBLOCK_THESE = ""

# Prevents the computer from seeing or connecting to any SSID's except the one defined. Use cautiously.
# Also overrides $BLOCK_THESE.
$HIDE_ALL = $false 

function change_SSID {
	Get-CurrentWLAN
	
	$PASSWORD = $PASSWORD -replace "&","&amp;"
	$using_ETHERNET = $false
	$using_WIFI = $false
	
	if ($SKIP_THESE -contains $global:CURRENT_SSID) { 
        Write-host "Connected to $($global:CURRENT_SSID), skipping!" 
		exit
    } 
	
	if (($UNBLOCK_THESE -join "").trim() -ne "") {
		$UNBLOCK_THESE | % {
			Netsh wlan delete filter permission=block ssid="$_" networktype=infrastructure
		}
	}
	
	Get-NetAdapter | Foreach-object {
		if ($_.Status -eq 'Up' -and $_.MediaType -match '802.3' -and $_.HardwareInterface -eq $true) { 
			Write-host "Already connected via $($_.Name) / $($_.InterfaceDescription)!`n"
			$using_ETHERNET = $true
		}
	}

	if (-not $using_ETHERNET) {
		if ($global:INTERFACE) { 
			Write-host "Wireless adapter found $($global:INTERFACE) / $($global:INTERFACE_DESC)!`n"
			$using_WIFI = $true 
		}
	}
	
	if ($USE_WPA3) { $WPA_MODE = "WPA3SAE" } else { $WPA_MODE = "WPA2PSK" }
	
	if ($global:INTERFACE) {
		$FOUND_SSID = find_ssid -ssid $NEW_SSID
		
		if ($FOUND_SSID[0]) { $WPA_MODE = $SCANNED_MODE[1] }
	}
	   
	$CONTINUE_ADD_PROFILE = ( ($ADD_PROFILE -and $using_WIFI) `
							-or $FORCE_ADD_PROFILE `
							-or $FORCE_CONNECT )`
							-and $global:CURRENT_SSID -ne $NEW_SSID 
							
	$CONTINUE_CONNECT  = $CONNECT_TO_SSID -and $using_WIFI -or $FORCE_CONNECT -and $FOUND_SSID
	
	if ($CONTINUE_ADD_PROFILE) {
		
		function create_profile {
			$hex = (Format-Hex -InputObject $NEW_SSID -Encoding ascii).ToString().replace('00000000','').replace($NEW_SSID,'').trim().replace(' ','')

			$xml_header = '<?xml version="1.0"?>
			<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
			'
			$xml_body = `
			"	<name>$($NEW_SSID)</name>
				<SSIDConfig>
					<SSID>
						<hex>$($hex)</hex>
						<name>$($NEW_SSID)</name>
					</SSID>
				</SSIDConfig>
				<connectionType>ESS</connectionType>
				<connectionMode>auto</connectionMode>
				<MSM>
					<security>
						<authEncryption>
							<authentication>$WPA_MODE</authentication>
							<encryption>AES</encryption>
							<useOneX>false</useOneX>
						</authEncryption>
						<sharedKey>
							<keyType>passPhrase</keyType>
							<protected>false</protected>
							<keyMaterial>$($PASSWORD)</keyMaterial>
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
		}
		
		create_profile

		(Netsh WLAN add profile filename="c:\users\public\SSIDProfile.xml" interface="$($global:INTERFACE)") | Tee-Object -variable output
		
		if ($output -match "not supported") { 
			Write-host Falling back to WPA2!`n
			$WPA_MODE = "WPA2PSK" 
			create_profile
			Netsh WLAN add profile filename="c:\users\public\SSIDProfile.xml" interface="$($global:INTERFACE)"
		}
		
		if ($PROFILE_AUTOCONNECT) {
			netsh wlan set profileparameter name="$($NEW_SSID)" connectionmode=auto
		}

		sleep 3

		if ($CONTINUE_CONNECT) {
			
			Write-host "Attempting connection to `"$NEW_SSID`""
			Netsh WLAN connect name="$($NEW_SSID)" interface="$($global:INTERFACE)"
			Remove-item "c:\users\public\SSIDProfile.xml" -Force
			sleep 2
			
			$back_online = check_online
			if ($back_online -eq $false) {
				Write-host "`nFailed to connect to `"$NEW_SSID`" or no internet! `nReconnecting to previous SSID `"$global:CURRENT_SSID`"!"
				Netsh WLAN connect name="$global:CURRENT_SSID" interface="$global:INTERFACE"
				return
			} 

		}
	} else {
		if ($global:CURRENT_SSID -eq $NEW_SSID) {
			Write-host "Already connected to `"$NEW_SSID`"!"
		}
		if (-not $global:INTERFACE) {
			Write-host No Wireless Adapter found!
		}
		else { 
			Write-host "Skipping `"$NEW_SSID`"!"
		}
	}
	
	cleanup_profiles
	
	if ($global:INTERFACE) {
		Write-host Successfully Configured SSIDs:
		( (netsh wlan show profiles) -join "`n" -split "-------------")[-1]
	}
	
	return
}

function cleanup_profiles {
	if ($BLOCK_THESE -eq $null) { exit }
	
	Get-CurrentWLAN

	$Profiles = (netsh.exe wlan show profiles) -match '\s:\s'

	if ($Profiles) {
		
		$Path = "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{$($global:WiFiGUID)}"
		$ProfilePaths = Get-ChildItem $Path | Select-Object -ExpandProperty FullName
		
		$ProfilesMarked = $ProfilePaths | % {
			[xml]$WiFiProfile = Get-Content $_
			$ProfileName = $WiFiProfile.WLANProfile.name
		
			if ($ProfileName -cin $BLOCK_THESE -and $ProfileName -ne $global:CURRENT_SSID) { 
				$_
			}
		}
		
		# netsh wlan delete profile name=""
		
		if ($ProfilesMarked) {
			Write-host `nDeleting the following SSID profiles:`n
			$ProfilesMarked  | % {
				$ProfileName = [XML](Get-Content $_)
				Write-host "    Deleted: $($ProfileName.WLANProfile.name)!"
				Remove-Item $_ -Force
			}
			restart-service wlansvc -force
		}
		
	}
	
    if ($HIDE_ALL) {
        netsh wlan add filter permission=allow ssid="$NEW_SSID" networktype=infrastructure
        netsh wlan add filter permission=denyall networktype=infrastructure 
    }
	else {
		if (($BLOCK_THESE -join "").trim() -ne "") {
			$BLOCK_THESE | % {
				if ($_ -ne $global:CURRENT_SSID -or $FORCE_BLOCK) { 
					$null = Netsh wlan add filter permission=block ssid="$_" networktype=infrastructure
				}
				else {
					Write-host `nScript prevented attempt to block currently connected SSID `"$global:CURRENT_SSID`"!
				}
			}
		}
	}
		
	Write-host `nSuccessfully Blocked SSIDs:
    ( (netsh wlan show filters) -join "`n" -split "-------------------------------")[-1]
    
}

function Get-CurrentWLAN {
	
    # Get WLAN interface information
    $netshOutput = netsh wlan show interfaces
	if ($netshOutput -match "not running|Error connecting") { Restart-service wlansvc -force -verbose }
	if ($netshOutput -match "no wireless interface") { return }
	
    $lines = $netshOutput -split "\r`n"`

    # Create an object to store WLAN information
    $CurrentInterface = New-Object PSObject

    # Parse and add interface details to the object
    foreach ($line in $lines) {
        $key, $value = $line -split ":\s+", 2

        if ($key -and $value -and ($key -notlike "*Hosted network status*")) {
		if ($key.trim() -eq "Name" -and $CurrentInterface.Name -ne $null) { continue }   
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
	
	if ($CurrentInterface -match "ms-settings:privacy-location") { 
		Write-host "Failed to retrieve WLAN settings!"
		return
	}
	
    # Set global variables
	$global:CURRENT_SSID = $CurrentInterface.SSID
	$global:INTERFACE = $CurrentInterface.Name
	$global:INTERFACE_DESC = $CurrentInterface.Description
	$global:WiFiGUID = $CurrentInterface.Guid
	    
	#return $CurrentInterface
	
}

function find_ssid($ssid) {
	
	if ((Get-netadapter | ? {$_.name -eq $global:INTERFACE}).status -eq 'Up') {
		
        Write-host Disconnecting from WiFi temporarily to search for SSID.
		$null = netsh wlan disconnect
		
		$counter = 1
		while ($ssid -cnotin $SCANNED_SSID_NAMES -and $counter -le 3) {
			$counter += 1
			Write-host "Searching for SSID...`n"
			
			$null = Netsh WLAN connect name="$NEW_SSID" interface="$INTERFACE"
			explorer.exe ms-availablenetworks: # Causes device to actively scan for new networks
			
			sleep 3
		
			$global:SCANNED_SSIDS  = (`
									( (netsh wlan show networks) -match "SSID.*|Authentication") `
									-replace "\d{1,3}.*:|Authentication\W*","" `
									-join'' `
									-split "SSID " `
									-match "Personal" `
									-replace "    "," : " `
									-match "\w+ :.*" `
									-inotmatch "DIRECT|TMOBILE|PRINTER"
								) | % {$_.trim()}
			
			if ($SCANNED_SSIDS) { $SCANNED_SSID_NAMES = ($SCANNED_SSIDS | % {$_.split(":").trim()[0]}) }
		}
		
		if ($ssid -cin $SCANNED_SSID_NAMES) { 
			Write-host Device successfully located SSID `"$ssid`"!`n
			 
			$SCANNED_MODES = ($SCANNED_SSIDS | ? { $_ -cmatch $ssid } | % { $_.split(":")[1].trim() })
			
			if ($SCANNED_MODES -imatch 'WPA3') { $WPA_MODE = "WPA3SAE" } else { $WPA_MODE = "WPA2PSK" }
			
			return $true, $WPA_MODE
		} 
		else { 
			Write-host Device failed to located SSID `"$ssid`"!`nReconnecting to previous SSID`n.
			
			$null = Netsh WLAN connect name="$global:CURRENT_SSID" interface="$global:INTERFACE"
			
			return $false, $false
		}	
	}
	else {
		Write-host Wireless adapter `( $($global:INTERFACE) / $($global:INTERFACE_DESC)`) is disconnected!`n
		return $false, $false
	}
	
}

function check_online {
	$reconnected = 0
	$failures    = 0
	
	while ($reconnected -lt 8) {
		$ping = ping 9.9.9.9 -n 1
		
		if ($ping -match "Reply from 9.9.9.9") {
			$reconnected += 1
		}
		else { 
			$reconnected  = 0
			$failures    += 1
		}
		
		if ($failures -eq 8) {
			return $false
		}
		
		sleep 1
	}	
	return $true
}

change_SSID