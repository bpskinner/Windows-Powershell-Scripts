﻿#!PS

# SSID's are Case sensitive.
# Please carefully fill out the options below.
$NEW_SSID = "MRNISSATL-Corp" 
$PASSWORD = "***"

# Adds the new SSID profile only only if the device IS wireless.
$ADD_PROFILE = $true  

# Connect to the new SSID only if the device IS NOT hardwired.
# Requires $ADD_PROFILE/$FORCE_ADD_PROFILE to be true.
$CONNECT_TO_SSID = $true 

# Adds the new SSID profile regardless of hardwired/wireless status.
$FORCE_ADD_PROFILE = $true

# Force the device to connect to the new SSID regardless of hardwired/wireless status.
# Also overrides $CONNECT_TO_SSID and $ADD_PROFILE/$FORCE_ADD_PROFILE.
$FORCE_CONNECT = $false 

# If device is connected to any of these SSID's, cancel script.
$SKIP_THESE = "Example1_SSID","Example2_SSID" 

# Removes SSID if it's saved and hides the network so the device can't try to connect.
$BLOCK_THESE = "MRNISSATL-Employee","MRNISSATL-CORP","MRNISSATL-Tablet","MRNISSATL-Vendor","MRNISSATL-Tech","MRNISSATL-Employee-PD","Nissan PREMIUM Guest-WiFi","MRNISSATL-PScan" 

# Prevents the computer from seeing or connecting to any SSID's except the one defined. Use cautiously.
# Also overrides $BLOCK_THESE.
$HIDE_ALL = $false 

restart-service wlansvc -force

function change_SSID {
	
    $PASSWORD = $PASSWORD -replace "&","&amp;"
	$WiFi = Get-CurrentWLAN
    $CURRENT_SSID = $WiFi.SSID
    
    if ($SKIP_THESE -contains $CURRENT_SSID) { 
        Write-host "Connected to $($CURRENT_SSID), skipping!" 
		exit
    } 
	
	$using_ETHERNET = $false
	$using_WIFI = $false

	Get-NetAdapter | Foreach-object {
		if ($_.Status -eq 'Up' -and $_.MediaType -match '802.3') { 
			Write-host "Already connected via $($_.Name) / $($_.InterfaceDescription)!`n"
			$using_ETHERNET = $true
		}
	}

	if (-not $using_ETHERNET) {
		if ($WiFi.Name) { 
			Write-host "Wireless adapter found $($WiFi.Name) / $($WiFi.Description)!`n"
			$using_WIFI = $true 
		}
	}
	   
	$CONTINUE_ADD_PROFILE = ( ($ADD_PROFILE -and $using_WIFI) `
							-or $FORCE_ADD_PROFILE `
							-or $FORCE_CONNECT )`
							-and $CURRENT_SSID -ne $NEW_SSID
							
	$CONTINUE_CONNECT  = $CONNECT_TO_SSID -and $using_WIFI -or $FORCE_CONNECT
	
	if ($CONTINUE_ADD_PROFILE) {
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
						<authentication>WPA2PSK</authentication>
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

		Netsh WLAN add profile filename="c:\users\public\SSIDProfile.xml"
		sleep 3

		if ($CONTINUE_CONNECT) {
			Write-host "Attempting connection to `"$NEW_SSID`""
			Netsh WLAN connect name="$($NEW_SSID)" interface="$($WiFi.Name)"
			Remove-item "c:\users\public\SSIDProfile.xml" -Force
			sleep 2
			
			$back_online = check_online
			if ($back_online -eq $false) {
				Netsh WLAN connect name="$CURRENT_SSID" interface="$($WiFi.Name)"
				return
			}
		}
	} else {
		Write-host "Already connected to $NEW_SSID!"
	}
	
	cleanup_profiles
	
	Write-host Successfully Configured SSIDs:
	( (netsh wlan show profiles) -join "`n" -split "-------------")[-1]
	
	return
}

function cleanup_profiles {

	if ($BLOCK_THESE -eq $null) { exit }
	
	$WiFi = Get-CurrentWLAN
	$CURRENT_SSID = $WiFi.SSID
	$Profiles = (netsh.exe wlan show profiles) -match '\s:\s'

	if ($Profiles) {
		
		$Path = "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{$($WiFi.Guid)}"
		$ProfilePaths = Get-ChildItem $Path | Select-Object -ExpandProperty FullName
		
		$ProfilesMarked = $ProfilePaths | % {
			[xml]$WiFiProfile = Get-Content $_
			$ProfileName = $WiFiProfile.WLANProfile.name
		
			if ($ProfileName -cin $BLOCK_THESE -and $ProfileName -ne $CURRENT_SSID) { 
				$_
			}
		}
		
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
		$BLOCK_THESE | % {
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

function check_online {
	$reconnected = 0
	$failures    = 0
	
	while ($reconnected -lt 10) {
		$ping = ping 9.9.9.9 -n 1
		
		if ($ping -match "Reply from") {
			$reconnected += 1
		}
		else { 
			$reconnected  = 0
			$failures    += 1
		}
		
		if ($failures -eq 20) {
			return $false
		}
		
		sleep 1
	}	
	return $true
}

change_SSID