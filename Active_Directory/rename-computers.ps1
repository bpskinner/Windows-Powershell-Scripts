$currentidentity = $([Security.Principal.WindowsIdentity]::GetCurrent())

$prefix = (Get-ADComputer -filter 'samaccountname -like "*"' `
| sort -Property name `
| ft -Property NAME -HideTableHeaders -AutoSize `
| out-string).trim().split([Environment]::NewLine).where({ $_ -ne "" }) `
| % { $_.split('-')[0] } | Group-Object | Sort-Object Count -Descending `
| Select-Object Name,Count -First 3

while ($true) {
    cls
    
    Write-host "`nFound $($prefix.count) prefixes!`n (Type `"x`" to cancel)`n"

    $i = 1
    foreach ($name in $prefix) {
        $name = ([string]($name.name) + " " + [string]($name.count))
        Write-host "  $i > " -NoNewline
        Write-host $name -ForegroundColor Red 
        $i++
    }

    $select = Read-host "`nSelect the prefix to use"
    try { 
        if ($select -ieq 'x') { 
            Write-host Cancelling script. Please start over. -ForegroundColor Yellow
            break 
        }
        if ($prefix[$select-1] -ne $null -and $select -ne 0) { 
            $prefix = $prefix[$select-1].name
            break 
        } else {
            Write-host Invalid selection! -ForegroundColor Red
        }
    } catch {
        Write-host Invalid input! -ForegroundColor Red
    } 

    pause
}

### START SCRIPT
while ($true) {
    cls
    while ($dcred -eq $null) {

        $domainuser = read-host "Admin account" #read-host "Admin Username"
        $domainpass = read-host "Admin Password" -AsSecureString
        $tempcred = [PsCredential]::New($domainuser, $domainpass)
        
        if (Get-ADUser -Identity $domainuser -Credential $tempcred) {
            $global:dcred = $tempcred
        }
        
    }

    $search = (Read-host "`nSpecify a department suffix that you want to rename,`nit will match any PC's that contain this value").trim().toUpper()
    $basename = (Read-host "`nNew dept suffix to change computers to").trim().toUpper()
    $days = (Read-host "`nSearch for computers older than (days) to delete their AD Objects `n(must be greater than 30 days)")
    if ($days -lt 30 -or $days -eq [string]::Empty) { $days = 30 }

    ### Find stale computer objects for removal

    $global:complist = $null
    $ADcomputers = Get-ADComputer -Filter "CN -like '*'" -Properties CN, LastLogonDate, Created, Enabled
    $ADComputers = $ADcomputers | ? { $_ -match $search } 
    foreach ($PC in $ADcomputers) { 
        if ($PC.LastLogonDate -eq $null) { 
            [array]$global:complist += $PC 
            continue
        }
        if ((NEW-TIMESPAN –End $(get-date) –Start $PC.LastLogonDate).TotalDays -gt $days) {
            [array]$global:complist += $PC 
            continue
        }
    }

    $global:complist = $global:complist | Sort-Object -Descending -Property LastLogonDate, Created
    if ($global:complist.count -ge 1) {
        while ($True) {
            
            Write-host "`nInitial computer count is < $(($ADcomputers | ? { $_.Enabled -eq $True } ).count) >" -ForegroundColor DarkYellow
            Write-host Listing all computer accounts unused for over $days days... -BackgroundColor DarkYellow -ForegroundColor Black
            Write-host "`n    | Computer                  | LastLogon | First Created" -ForegroundColor DarkGray
            Write-host "    \_________________________________________________/`n" -ForegroundColor DarkGray
            
            $i = 0
            foreach ($x in $global:complist) {
                $i += 1
                try { $lastlogon = ($x.LastLogonDate).tostring('MM-dd-yy') } catch { $lastlogon = 'NULLDATE' }
                Write-host $("   $i>" + ' ' * (4 - ([string]$i).length)) -NoNewline; write-host $($x.CN + ' ' * (23 - ($x.CN).Length) + ' | ') $($lastlogon) "|" $(($x.Created).tostring('MM-dd-yy')) -ForegroundColor Red 
            } 
            
            Write-host `nEnter to skip -BackgroundColor White -ForegroundColor Black
            Write-host "`n  <" -nonewline; write-host X -NoNewline -ForegroundColor DarkRed; write-host "> " -NoNewline; write-host ">>DELETE<< all computer objects listed above" -ForegroundColor Gray
            Write-host "  <#> " -NoNewline; write-host "Type the # of a PC you DO NOT want to disable" -ForegroundColor Gray
            Write-host "      " -NoNewline; write-host "OR include @ to DISABLE the computer object (e.g. '5@')"  -ForegroundColor Gray

            $choice = Read-host "`n>"
            
            if ($choice -eq [string]::Empty) { break }

            if ($choice -ieq 'X') { 
                foreach ($u in $global:complist) { 
                    Remove-ADComputer -Identity $u -Confirm:$false
                    Write-host Deleting computer account [ $($u.CN) / $u.LastLogonDate ] -ForegroundColor green
                }
                break
            }

            if ($choice -like '*@*') { 
                $choice = $choice.replace('@', '').Replace(' ', '')
                if ($global:complist[$choice - 1] -ne $null -or $choice -ne 0) {
                    if ($confirm -ieq 'X') {
                        Write-host Removing computer object [ $($global:complist[$choice - 1].CN) ] -ForegroundColor green
                        Remove-Adcomputer -Identity $global:complist[$choice - 1] -confirm:$false
                        $global:complist = $global:complist | ? { $_ -ne ($global:complist[$choice - 1]) }
                        continue
                    }
                    else {
                        Write-host `nCancelling...`n
                        continue
                    }            
                }
            }

            Try { [int]$choice } catch { cls; Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; pause; continue }
            
            if ($global:complist[$choice - 1] -eq $null -or $choice -eq 0) {
                cls
                Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; continue
            }
            else { 
                cls
                Write-host Removing [ $(($global:complist[$choice - 1]).CN) ] from the DELETE COMPUTERS list...
                $global:complist = $global:complist | ? { $_ -ne ($global:complist[$choice - 1]) }
            }

        }
        $pccount = (Get-ADComputer -Filter "CN -like '*'" -Properties LastLogonDate, Enabled | ? { $_.LastLogonDate -ne $null } | ? { $_.Enabled -eq $True -and (NEW-TIMESPAN –End $(get-date) –Start $_.LastLogonDate).TotalDays -lt 90 }).count
    }

    ### Cleanup DNS

    $servername = hostname
    $serverip = (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -PrefixLength 24 -PrefixOrigin Manual)[0].IPAddress
    $currentdomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select -ExpandProperty Domain
    $prefix = $currentdomain.split(".")[0]
    $suffix = $currentdomain.split(".")[1]
    $zonename = $($prefix + "." + $suffix)
    $fqdn = $($servername + "." + $zonename + ".")

    $dnsrecords = Get-DnsServerResourceRecord -ZoneName $zonename `
        | Where-Object { $_.timestamp -ne $null } `
        | Where-Object { (NEW-TIMESPAN –End $(get-date) –Start $_.timestamp).TotalDays -gt 30 } `
        | Sort-Object timestamp 

    if ($dnsrecords.count -ge 1) {
        $dnsrecords | Remove-DnsServerResourceRecord -ZoneName $zonename -force
        ipconfig /flushdns
        Write-host "`nRemoved $($dnsrecords.count) stale DNS Records!" -ForegroundColor Yellow
        Write-host "Please run 'ipconfig /registerdns' on all target computers!`n" -ForegroundColor Yellow
        Pause
    }

    ### Generate new computer names

    $discovered = (Get-ADComputer -filter "samaccountname -like '*$search*'" `
        | sort -Property name `
        | ? { $_.Enabled -eq $True } `
        | ? { $_.Name -imatch "$search\w*\-?_?\d*" }).name

    $existing = (Get-ADComputer -filter "samaccountname -like '*$basename*'" `
        | sort -Property name `
        | ? { $_.Enabled -eq $True } `
        | ? { $_.Name -imatch "$basename\d*" }).name `
        | ? { $_ -imatch ($prefix + "-" + $basename) }

    while ($true -and $discovered.count -ge 1) {
        $i = 1
        Write-host "`nFound $($discovered.count) computers!"
        $discovered | ForEach-Object { 
            Write-host "$i$(' ' * (4 - ([string]$i).length))> " -NoNewline
            Write-host $_ -ForegroundColor Red 
            $i++
        }
        $substring = Read-host "`nPlease type any value to REMOVE IT FROM THE SEARCH`n(i.e. 'MGR' if you want to remove 'BDCMGR' and only target regular 'BDC' PC's)`n`nPress enter to continue >"  
        if ($substring -eq [string]::Empty) { break }
        $discovered = $discovered | Where-Object { $_ -inotmatch $substring }  
        
    }

    $tempcomputers = [System.Collections.Generic.List[string]]::new()
    $computers = [System.Collections.Generic.List[string]]::new()
    $newnames = [System.Collections.Generic.List[string]]::new()
    $discovered | ForEach-Object { $tempcomputers.add($_); $computers.add($_) }

    #(($existing -replace "\D|0", "") | measure -Maximum).Maximum

    foreach ($index in 1..($computers.count + $existing.count)) {
        if ($newnames.count -ge $computers.count) { 
            break 
        }

        if (([string]$index).length -le 1) { 
            $newname = ($prefix + "-" + $basename + "0") + $index 
        }
        else { 
            $newname = ($prefix + "-" + $basename) + $index 
        }

        if ($newname -in $existing) { 
            $null = $computers.remove($newname)
            continue 
        }

        $newnames.add($newname)
    }

    foreach ($computer in $tempcomputers) {
        if ($computer -in $newnames) { 
            $null = $newnames.remove($computer)
            $null = $computers.remove($computer)
        }
    }

    ### Rename old computer names to new names

    if (-not($computers.count -ge 1)) {
        Write-host `nNo computers matching search have been found!`n -ForegroundColor Red -BackgroundColor DarkGray
    }
    else {
        while ($true) {
            Write-host "`nThe following computers will be renamed:"
            foreach ($index in 0..($computers.count - 1)) {
                $i = $index+1
                $oldname = $computers[$index]
                $newname = $newnames[$index]
                
                Write-host "$i$(' ' * (4 - ([string]$i).length))> " -NoNewline
                Write-host " $oldname to $(' ' * [math]::Max(0,(15 - ([string]$oldname).length))) < " -ForegroundColor Red -NoNewline
                Write-host $newname -NoNewline 
                Write-host " >" -ForegroundColor Red
            }
        
            $continue = Read-host "`nType Y to Proceed or X to Cancel"
            if ($continue -ieq "Y" -or $continue -ieq "X") { break }
            cls
        }

        if ($continue -ieq 'Y') {
            $old_index = 0
            $new_index = 0
            while ($true) {
                $oldname = $computers[$old_index]
                $newname = $newnames[$new_index]
                if ($old_index -gt $newnames.count - 1 -or $oldname -eq $null) { break }
                $old_index++


                if ($newname -eq $oldname) { 
                    Write-host Name $newname already exists!
                    continue 
                }

                $ping = ping $oldname -n 2 | Where-Object { $_ -match "Reply from" }
                $ping = $true # Override due to some computers not responding to ICMP.
                if ($ping -eq $null) {
                    Write-host "Failed to rename computer < $oldname > Ping failed!" -ForegroundColor Red
                    continue
                }

                try {
                    Rename-Computer -ComputerName $oldname -NewName $newname -DomainCredential $dcred -ErrorVariable Err -ErrorAction Stop
                    
                    Write-host " $("$old_index$(' ' * (2 - ([string]$old_index).length)) > ")" -NoNewline;
                    Write-host "$($oldname + $(' ' * (18 - ([string]$oldname).length)) ) has been renamed to" -ForegroundColor Red -NoNewline
                    Write-host $newname 
                    $new_index++
                }
                catch {
                    if ($Err -imatch "Account already exists") { $new_index++ ; $old_index = $old_index - 1 }
                    Write-host "Failed to rename computer < $oldname > ...`n$($Error[0])" -ForegroundColor Red
                }

            }
        }
    }
    while ($true) {
        $continue = Read-host "`nStart over? Y to continue"
        if ($continue -ieq 'y') { break }
    }
}

### END SCRIPT

# Remove-Computer -UnjoinDomainCredential $dcred -WorkgroupName WORKGROUP
# Get-CimInstance -ClassName Win32_OperatingSystem | Select -Exp LastBootUpTime; if ((Test-ComputerSecureChannel) -eq $false){"Needs reboot"}
# Enable-PSRemoting -Force -SkipNetworkProfileCheck

#$trustrelationship = Invoke-Command -ComputerName $oldname -Credential $dcred -ScriptBlock { Test-computersecurechannel } -ErrorAction SilentlyContinue
#if (-not $trustrelationship) {
#    Write-host "Failed to rename computer < $oldname > No trust relationship found!" -ForegroundColor Red
#    continue
#}