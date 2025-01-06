Import-Module ActiveDirectory

$allowedusers = @(
    'docserv',
    'payroll',
    'hr',
    'controller',
    'officermgr',
    'acctg',
    'bdc',
    'internet',
    'bodyshop',
    'fi',
    'internetmgr',
    'salesmgr',
    'fimgr',
    'bdcmgr',
    'partsmgr',
    'servmgr',
    'parts',
    'sales',
    'greeter',
    'porter',
    'serv',
    'cashier',
    'servtech',
    'panuserid',
    'warranty',
    'itmgmt'
    )

function ulist {
    
    cls
    if ((test-path C:\pslogs\) -eq $false) { New-Item -ItemType Directory -Path C:\pslogs -Force }
    Start-Transcript -Path C:\pslogs\Disable_Old_ADUsers.txt -Append

    $global:list = $null

    $group = Get-ADGroupMember "domain admins" | select -ExpandProperty samaccountname

    $ADusers = (Get-ADUser -filter * -Properties LastLogonDate,Created,Enabled,LastBadPasswordAttempt `
    | select-object SamAccountName,LastLogonDate,Enabled,Created,LastBadPasswordAttempt) `
    | ? { $_.Enabled -eq $True -and $_.samaccountname -inotin $allowedusers }
    
    Foreach ($user in $ADusers) { 

        if ($user.LastLogonDate -eq $null -and (NEW-TIMESPAN –End $(get-date) –Start $user.Created).TotalDays -gt 90) { 
            if ($group -notcontains $user.samaccountname) {
                [array]$global:list += $user
                }
            }

        if ($user.LastLogonDate -ne $null -and (NEW-TIMESPAN –End $(get-date) –Start $user.lastlogondate).TotalDays -gt 90) { 
            if ($group -notcontains $user.samaccountname) {
                    [array]$global:list += $user
                    }
                }

        }

    $global:list = $global:list | Sort-Object -Descending -Property LastLogonDate,Created

    while ($True) {
        
        Write-host "`nListing users that haven't logged in for more than 90 Days..." -BackgroundColor DarkYellow -ForegroundColor Black
        Write-host "`n    | User                      | LastLogon | First Created" -ForegroundColor DarkGray
        Write-host "    \_________________________________________________/`n" -ForegroundColor DarkGray
        
        $i = 0
        foreach ($x in $global:list) {
            $i += 1
            try { $lastlogon = ($x.LastLogonDate).tostring('MM-dd-yy') } catch { $lastlogon = 'NULLDATE' }
            Write-host $("   $i>" + ' ' * (4 - ([string]$i).length)) -NoNewline; write-host $($x.samaccountname + ' ' * (23 - ($x.samaccountname).Length))   ' | ' $($lastlogon) "|" $(($x.Created).tostring('MM-dd-yy'))  -ForegroundColor Red 
            } 
            
        Write-host `nEnter to Cancel -BackgroundColor White -ForegroundColor Black
        Write-host "`n  <" -nonewline; write-host X -NoNewline -ForegroundColor DarkRed; write-host "> " -NoNewline; write-host Disable all users listed above -ForegroundColor Gray
        Write-host "  <#> " -NoNewline; write-host "Type # of a user you DO NOT want to disable" -ForegroundColor Gray
        Write-host "  <R!> " -NoNewline; write-host "Re-Enable Generic Users" -ForegroundColor Gray
        
        $choice = Read-host "`n>"
        
        if ($choice -eq [string]::Empty) { break }

        if ($choice -ieq 'X') { 
            $confirm = Read-host `nType X again to confirm. `nThis will DISABLE all users listed above `n`n>
            if ($confirm -ieq 'X') {
                foreach ($u in $global:list) { 
                    Write-host DISABLING user [ $($u.samaccountname) ] -ForegroundColor green
                    Set-AdUser -Identity $u.samaccountname -Enabled 0 
                    }
                break
                } else {
                    Write-host `nCancelling...`n
                    continue
                    }            
            }

        if ($choice -ieq 'R!') { 
            cls
            foreach ($user in $allowedusers) {
                if (Get-ADUser -Filter 'samaccountname -eq $user') {
                    #Get-ADUser -Filter 'samaccountname -eq $user'
                    Set-AdUser -Identity $user -Enabled 1
                    Write-host Enabling [ $user ]
                    }
                }
            Write-host `nDone re-enabling allowedusers.`n
            continue
            }

        Try { [int]$choice } catch { cls; Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; pause; continue }

        if ($global:list[$choice -1] -eq $null -or $choice -eq 0) {
            cls
            Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; continue
            } else { 
                cls
                Write-host Removing [ $(($global:list[$choice -1]).samaccountname) ] from the DISABLE USERS list...
                $global:list = $global:list | ? {$_ -ne ($global:list[$choice -1])}
                }

        }

    Stop-Transcript
    
    }

function alist {
    
    cls
    if ((test-path C:\pslogs\) -eq $false) { New-Item -ItemType Directory -Path C:\pslogs -Force }
    Start-Transcript -Path C:\pslogs\Disable_Old_ADAdmins.txt -Append

    $global:adminlist = $null
    
    $group = $null
    [array]$group = Get-ADGroupMember "domain admins" | select -ExpandProperty samaccountname
    [array]$group += Get-ADGroupMember "Administrators" | select -ExpandProperty samaccountname
    [array]$group += Get-ADGroupMember "Schema Admins" | select -ExpandProperty samaccountname
    [array]$group += Get-ADGroupMember "Enterprise Admins" | select -ExpandProperty samaccountname

    $ADadmins = (Get-ADUser -filter * -Properties LastLogonDate,Created,Enabled,LastBadPasswordAttempt `
    | select-object SamAccountName,LastLogonDate,Enabled,Created,LastBadPasswordAttempt) `
    | ? {$_.Enabled -eq $True}

    foreach ($user in $ADadmins) { 
        if ($group -contains $user.samaccountname) { 
            [array]$global:adminlist += $user
            }
        }
    
    $global:adminlist = $global:adminlist | Sort-Object -Descending -Property LastLogonDate,Created

    while ($True) {
        
        Write-host `nListing all Domain Admins... -BackgroundColor DarkYellow -ForegroundColor Black
        Write-host "`n    | User              | LastLogon | Created  | Failed Login | In Groups" -ForegroundColor DarkGray
        Write-host "    \______________________________________________________________________/`n" -ForegroundColor DarkGray
        
        $i = 0
        foreach ($x in $global:adminlist) {
            $i += 1
            
            try { $lastlogon = ($x.LastLogonDate).tostring('MM-dd-yy') } catch { $lastlogon = 'NULLDATE' }
            try { $lastfailedlogon = ($x.LastBadPasswordAttempt).tostring('MM-dd-yy') } catch { $lastfailedlogon = 'NULLDATE' }
            try { $ingroup = Get-ADPrincipalGroupMembership $x.samaccountname | ? { $_.name -iin 'Administrators', 'Schema Admins', 'Enterprise Admins', 'Domain Admins' } | select -ExpandProperty name } catch { $ingroup = 'NULLDATA' }

            Write-host $("   $i>" + ' ' * (4 - ([string]$i).length)) -NoNewline; write-host $($x.samaccountname + ' ' * (15 - ($x.samaccountname).Length) + ' |') $($lastlogon) " |" $(($x.Created).tostring('MM-dd-yy')) "|" $($lastfailedlogon) "    |" $($ingroup -join ', ') -ForegroundColor Red 
            } 

        Write-host `nEnter to Cancel -BackgroundColor White -ForegroundColor Black
        Write-host "`n  <#> " -NoNewline; write-host "Type # of a user to DISABLE"  -ForegroundColor Gray
        Write-host "      " -NoNewline; write-host "OR include @ to REMOVE from *any* ADMIN groups (e.g. '5@')"  -ForegroundColor Gray
        
        $choice = Read-host "`n>"
        
        if ($choice -eq [string]::Empty) { break }
        
        if ($choice -like '*@*') {
            $choice = $choice.replace('@','').Replace(' ','')
            $usr = $global:adminlist[$choice -1].samaccountname
            if ($usr -ne $null -or $choice -ne 0) {
                cls
                $primarygroup = get-adgroup "Domain Users" -properties @("primaryGroupToken")
                get-aduser $usr | set-aduser -replace @{primaryGroupID=$primarygroup.primaryGroupToken}
                $usrgrp = Get-ADPrincipalGroupMembership $usr | ? { $_.name -iin 'Administrators', 'Schema Admins', 'Enterprise Admins', 'Domain Admins' } | select -ExpandProperty name
                    foreach ($group in $usrgrp) {
                    Write-host REMOVING user [ $usr ] from $group group -ForegroundColor green
                    net group "$($group)" /delete $usr # | out-null
                    }
                $global:adminlist = $global:adminlist | ? {$_.samaccountname -ne ($usr)}
                continue
                }
            }

        Try { [int]$choice } catch { cls; Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; pause; continue }
        
        if ($global:adminlist[$choice -1] -eq $null -or $choice -eq 0) {
            cls
            Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; continue
            pause
            } else {
                $confirm = Read-host `nType X again to confirm. `nDisable user [ $($global:adminlist[$choice -1].samaccountname) ] `n`n>
                if ($confirm -ieq 'X') {
                    cls
                    Write-host DISABLING user [ $($global:adminlist[$choice -1].samaccountname) ] -ForegroundColor green
                    Set-AdUser -Identity $global:adminlist[$choice -1].samaccountname -Enabled 0 -Verbose
                    $global:adminlist = $global:adminlist | ? {$_ -ne ($global:adminlist[$choice -1])}
                    continue
                    } else {
                        Write-host `nCancelling...`n
                        continue
                        }
                }

        }

    Stop-Transcript

    }

function clist {
    
    cls
    if ((test-path C:\pslogs\) -eq $false) { New-Item -ItemType Directory -Path C:\pslogs -Force }
    Start-Transcript -Path C:\pslogs\Delete_Old_PCObjects.txt -Append

    $global:complist = $null
    $search = (Read-host "Search for specific computers: ").trim()
    $days = (Read-host "Search for computers older than (days): ")
    $ADcomputers = Get-ADComputer -Filter "CN -like '*'" -Properties CN,LastLogonDate,Created,Enabled
    $ADComputers = $ADcomputers | ? { $_ -match $search } 

    foreach ($PC in $ADcomputers) { 
        if ($PC.LastLogonDate -eq $null) { 
            [array]$global:complist += $PC 
            continue
            }
        if ($PC.Enabled -eq $True -and (NEW-TIMESPAN –End $(get-date) –Start $PC.LastLogonDate).TotalDays -gt $days) {
            [array]$global:complist += $PC 
            continue
            }
        if ((NEW-TIMESPAN –End $(get-date) –Start $PC.LastLogonDate).TotalDays -gt 150) {
            [array]$global:complist += $PC 
            continue
            }
        }
    
    $global:complist = $global:complist | Sort-Object -Descending -Property LastLogonDate,Created

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
        
        Write-host `nEnter to Cancel -BackgroundColor White -ForegroundColor Black
        Write-host "`n  <" -nonewline; write-host X -NoNewline -ForegroundColor DarkRed; write-host "> " -NoNewline; write-host DISABLE all computer objects listed above -ForegroundColor Gray
        Write-host "  <#> " -NoNewline; write-host "Type the # of a PC you DO NOT want to disable" -ForegroundColor Gray
        Write-host "      " -NoNewline; write-host "OR include @ to DISABLE the computer object (e.g. '5@')"  -ForegroundColor Gray

        $choice = Read-host "`n>"
        
        if ($choice -eq [string]::Empty) { break }

        if ($choice -ieq 'X') { 
            $confirm = Read-host `nType X again to confirm. `nThis will remove all computers listed above `n`n>
            if ($confirm -ieq 'X') {
                foreach ($u in $global:complist) { 
                    if ($u.LastLogonDate -eq $null) {
                        Write-host Disabling computer account [ $($u.CN) / NULLDATE ] -ForegroundColor green
                        Remove-ADComputer -Identity $u.CN -Confirm:$false
                        continue
                        }
                    if ((NEW-TIMESPAN –End $(get-date) –Start $u.LastLogonDate).TotalDays -gt 150) {
                        #Write-host Deleting computer account [ $($u.CN) / $u.LastLogonDate ] -ForegroundColor green
                        #try { Remove-ADComputer -Identity $u.SID -Confirm:$false } catch { Get-ADObject -Identity $u | Remove-ADObject -Recursive -Confirm:$false }
                        Write-host Disabling computer account [ $($u.CN) / $u.LastLogonDate ] -ForegroundColor darkgreen
                        Disable-ADAccount -Identity $u
                        continue
                        } else {
                            Write-host Disabling computer account [ $($u.CN) / $u.LastLogonDate ] -ForegroundColor darkgreen
                            Disable-ADAccount -Identity $u
                            continue
                            }
                    }
                break
                } else {
                    Write-host `nCancelling...`n
                    continue
                    }
            }

        if ($choice -like '*@*') { 
            $choice = $choice.replace('@','').Replace(' ','')
            if ($global:complist[$choice -1] -ne $null -or $choice -ne 0) {
                $confirm = Read-host `nType X again to confirm. `nDisable computer [ $($global:complist[$choice -1].CN) ] `n`n>
                if ($confirm -ieq 'X') {
                    Write-host Removing computer object [ $($global:complist[$choice -1].CN) ] -ForegroundColor green
                    Disable-ADAccount -Identity $global:complist[$choice -1]
                    $global:complist = $global:complist | ? {$_ -ne ($global:complist[$choice -1])}
                    continue
                    } else {
                        Write-host `nCancelling...`n
                        continue
                        }            
                }
            }

        Try { [int]$choice } catch { cls; Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; pause; continue }
        
        if ($global:complist[$choice -1] -eq $null -or $choice -eq 0) {
            cls
            Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; continue
            } else { 
                cls
                Write-host Removing [ $(($global:complist[$choice -1]).CN) ] from the DELETE COMPUTERS list...
                $global:complist = $global:complist | ? {$_ -ne ($global:complist[$choice -1])}
                }

        }
    
    $pccount = (Get-ADComputer -Filter "CN -like '*'" -Properties LastLogonDate,Enabled | ? { $_.LastLogonDate -ne $null } | ? { $_.Enabled -eq $True -and (NEW-TIMESPAN –End $(get-date) –Start $_.LastLogonDate).TotalDays -lt 90 }).count
    Write-host "`nTotal computer count is < $pccount >`n" -ForegroundColor Yellow
    Stop-Transcript

    }

function pwlist {

    # // INTERNAL FUNCTIONS //

    function updateusers { 

        return (Get-ADUser -filter * -Properties PasswordLastSet,PasswordExpired,PasswordNeverExpires,LastLogonDate,Enabled,Created `
        | select-object SamAccountName,PasswordLastSet,PasswordExpired,PasswordNeverExpires,LastLogonDate,Enabled,Created)

        }
    
    function updateadmins {
       
        [array]$group = Get-ADGroupMember "domain admins" 
        [array]$group += Get-ADGroupMember "Administrators" 
        [array]$group += Get-ADGroupMember "Schema Admins" 
        [array]$group += Get-ADGroupMember "Enterprise Admins"
        
        foreach ($object in $group) { 
            if ($ADusers.samaccountname -contains $object.samaccountname) { 
                $object = Get-AdUser -Identity $object -Properties PasswordLastSet,PasswordExpired,PasswordNeverExpires,LastLogonDate,Enabled,Created
                [array]$list += $object
                }
            }

        return $list | select -Unique
        } # (updateadmins)
    
    function getusers($var) {
        
        $global:ADusers = updateusers
        $global:USERPWlist = $null
        
        if ($var -eq 'showall') {  
            $global:checkadmins = 'INCLUDED'
            $global:showgeneric = 'INCLUDED'
            $global:USERPWlist = $global:ADusers
            } #getusers('showall')
        
        if ($global:showgeneric -eq 'NO') {
            $global:ADusers = $global:ADusers | ? { $_.samaccountname -inotin $allowedusers }
            } #showgeneric -eq $false

        if ($var -eq 'showadmins') {
            $global:checkadmins = 'YES'
            $global:admingroup = updateadmins
            $global:USERPWlist = $global:admingroup
            } #var -eq 'showadmins'
                
        if ($var -eq 'expired') {
            $expiredlist = $null
            Foreach ($user in $ADusers) { 
                if (
                    $user.PasswordExpired -eq $true
                    ) { [array]$expiredlist += $user }
                }
            $global:USERPWlist = $expiredlist
            } #var -eq 'expired'
        
        if ($var -eq 'normal') {
                $global:checkadmins = 'NO'
                Foreach ($user in $ADusers) { 

                    if ($global:admingroup.samaccountname -notcontains $user.samaccountname) {
                                
                        if (
                            $user.PasswordExpired -eq $true -or `
                            $user.Enabled -eq $False
                            ) { continue }

                        if (
                            $user.PasswordLastSet -eq $null -and `
                            $user.PasswordExpired -eq $false -and `
                            $user.Enabled -eq $True
                            ) { [array]$global:USERPWlist += $user; continue }

                        if (
                            $user.LastLogonDate -eq $null -and `
                            $user.Enabled -eq $True
                            ) { [array]$global:USERPWlist += $user; continue }

                        if (
                            $user.LastLogonDate -ne $null -and `
                            ((NEW-TIMESPAN –Start $user.PasswordLastSet).TotalDays -gt 60) -and `
                            $user.PasswordExpired -eq $false -and `
                            $user.Enabled -eq $True
                            ) { [array]$global:USERPWlist += $user; continue }

                        }

                    }
                } #getusers('normal')

        $global:USERPWlist = $global:USERPWlist | Sort-Object -Descending -Property LastLogon,PasswordLastSet

        } #getusers

    function enumerate($list) {
        
        Write-host "`n        User                 | PW Last Set | PW Expired | Nvr Expires | Last Logon | Enabled" -ForegroundColor DarkGray
        Write-host "   .________________________________________________________________________________________." -ForegroundColor DarkGray
        
        if ($list.count -eq 0) { Write-host "`n   `*`> `-`- NO USERS MATCH SEARCH CRITERIA --`n" }
        else {
            $i = 0
            foreach ($x in $list) {
                $i += 1
            
                try { $pwlastset = ($x.PasswordLastSet).tostring('MM-dd-yy') } catch { $pwlastset = 'NULLDATE' }
                try { $lastlogon = ($x.LastLogonDate).tostring('MM-dd-yy') } catch { $lastlogon = 'NULLDATE'}
                if ($x.samaccountname -in $global:admingroup.samaccountname) { 
                    $usrname = "$($x.samaccountname) *" 
                    } else {
                        if ($x.samaccountname -in $allowedusers) { 
                            $usrname = "[ $($x.samaccountname) ]" 
                            } else { 
                                $usrname = $x.samaccountname 
                                }
                        }

                Write-host $("   $i>") -NoNewline
                Write-host $('-' * (3 - ([string]$i).length) + ' ') -NoNewline -ForegroundColor DarkGray
            
                if ($x.Enabled -eq $True) {
                    Write-host $($usrname + ' ') -NoNewline -ForegroundColor Red
                    } else { Write-host $($usrname + ' ') -NoNewline -ForegroundColor DarkGray }
            
                Write-Host $('-' * (20 - ($usrname).Length)) -NoNewline -ForegroundColor DarkGray; write-host '| ' -NoNewline

                if ($pwlastset -eq 'NULLDATE') { 
                    Write-host $($pwlastset) -NoNewline -ForegroundColor DarkGray; write-host "    | " -NoNewline 
                    } else { 
                        if ((NEW-TIMESPAN –Start ([datetime]$pwlastset)).TotalDays -gt 90) { 
                            Write-host $($pwlastset) -NoNewline -ForegroundColor DarkYellow; write-host "    | " -NoNewline 
                            } else { 
                                Write-host $($pwlastset) -NoNewline -ForegroundColor Yellow; write-host "    | " -NoNewline 
                                }
                        }
            
                if ($x.PasswordExpired -eq $True) { Write-host "$([string]$x.PasswordExpired) " -NoNewline -ForegroundColor DarkGray; Write-host "      | " -NoNewline  } 
                else { Write-host "$([string]$x.PasswordExpired)" -NoNewline -ForegroundColor DarkRed; Write-host "      | " -NoNewline  } 
                if ($x.PasswordNeverExpires -eq $True) { Write-host "$([string]$x.PasswordNeverExpires) " -NoNewline -ForegroundColor DarkRed; Write-host "       | " -NoNewline  } 
                else { Write-host "$([string]$x.PasswordNeverExpires)" -NoNewline -ForegroundColor DarkGray; Write-host "       | " -NoNewline  } 
            
                if ($lastlogon -eq 'NULLDATE') {
                    Write-host $($lastlogon) -NoNewline -ForegroundColor DarkGray; Write-host "   | " -NoNewline
                    } else {
                        if ((NEW-TIMESPAN –Start ([datetime]$lastlogon)).TotalDays -gt 90) { 
                            Write-host $($lastlogon) -NoNewline -ForegroundColor DarkYellow; Write-host "   | " -NoNewline
                            } else {
                                Write-host $($lastlogon) -NoNewline -ForegroundColor Yellow; Write-host "   | " -NoNewline
                                }
                        }

                if ($x.Enabled -eq $True) { Write-host "True   " -NoNewline -ForegroundColor DarkRed }
                if ($x.Enabled -eq $False) { Write-host "False  " -NoNewline -ForegroundColor DarkGray }
                if ($lastlogon -eq 'NULLDATE') { Write-host "| NOT IN USE " -ForegroundColor Gray -NoNewline }
                if ($pwlastset -eq $lastlogon) { Write-host "| ONLY USED ONCE " -ForegroundColor Gray -NoNewline }
                Write-host
                
                }
            }
        
        Write-host "    \_______________________________________________________________________________________/" -ForegroundColor DarkGray

        } # (Enumerate)
    
    # // BEGIN MAIN FUNCTION //

    cls

    $global:USERPWlist = $null
    $global:admingroup = $null
    $global:ADusers = $null
    
    $global:showgeneric = 'NO'
    $global:checkadmins = 'NO'
    $global:ADusers = updateusers
    $global:admingroup = updateadmins

    sleep 1
    getusers('normal')
    
    while ($True) {
        
        Write-host "`nListing users with Passwords older than 60 days..." -BackgroundColor White -ForegroundColor Black
        
        enumerate($global:USERPWlist)

        Write-host `n'Q' to Quit -BackgroundColor White -ForegroundColor Black
        Write-host `n`(`"*`" = Admin User`, `"[]`" = Generic User`, Dark Yellow = Older than 90 days`) -ForegroundColor DarkGray
        Write-host "`n   <" -nonewline; write-host X -NoNewline -ForegroundColor Red; write-host "> " -NoNewline; write-host Force ALL accounts to reset password on next logon -ForegroundColor Gray
        Write-host "   <#> " -NoNewline; write-host "Type # of a user to force reset password on next logon," -ForegroundColor Gray
        Write-host "    |  " -NoNewline; write-host "include @ to DISABLE user (e.g. '5@'),"  -ForegroundColor Gray
        Write-host "    |  " -NoNewline; write-host "OR include * to REMOVE user from *all* ADMIN groups (e.g. '5*')"  -ForegroundColor Gray
        Write-host "`n  <Check> " -NoNewline; write-host Type `"Check`" followed by a username to view their AD object and Group Membership -ForegroundColor Gray
        Write-host "`n  <G> " -NoNewline; write-host "View GENERIC users - " -NoNewline -ForegroundColor Gray; Write-host $global:showgeneric -ForegroundColor Red
        Write-host "  <D> " -NoNewline; write-host "View DOMAIN ADMIN users - " -NoNewline -ForegroundColor Gray; Write-host $global:checkadmins -ForegroundColor Red
        Write-host "  <E> " -NoNewline; write-host View EXPIRED users -ForegroundColor Gray
        Write-host "  <A> " -NoNewline; write-host View ALL users -ForegroundColor Gray
        Write-host `n Sort by -ForegroundColor DarkGray
        Write-host " `<1!> Never Expires` - `<2!> PW Last Set` - `<3!> User` - `<4!> Last Logon Date - `<5!> Enabled" -ForegroundColor Gray
        
        $choice = Read-host "`n>"

        if ($choice -eq [string]::Empty) { cls; getusers('normal'); continue }

        if ($choice -ieq 'Q') { break }

        $choiceint = $choice.replace('@','').replace('*','').Replace(' ','')
        try { $choiceint = [int]$choiceint } catch { $choiceint = [string]$choiceint }
        
        if ($choiceint -is [string]) {
        
            if ($choice -eq "1!") { 
                cls
                $global:USERPWlist = $global:USERPWlist | Sort-Object -Descending -Property PasswordNeverExpires,PasswordLastSet
                }

            if ($choice -eq "2!") {
                cls
                $global:USERPWlist = $global:USERPWlist | Sort-Object -Descending -Property PasswordLastSet,LastLogon
                }
        
            if ($choice -eq "3!") {
                cls
                $global:USERPWlist = $global:USERPWlist | Sort-Object -Property SamAccountName,PasswordLastSet
                }

            if ($choice -eq "4!") {
                cls
                $global:USERPWlist = $global:USERPWlist | Sort-Object -Descending -Property LastLogonDate,PasswordLastSet
                }
        
            if ($choice -eq "5!") {
                cls
                $global:USERPWlist = $global:USERPWlist | Sort-Object -Descending -Property Enabled,LastLogonDate
                }

            if ($choice -ieq "G") {
                cls
                if ($global:showgeneric -eq 'NO') { $global:showgeneric = 'YES' } else { $global:showgeneric = 'NO' }
                getusers('normal')
                }

            if ($choice -ieq "D") {
                cls
                getusers('showadmins')
                }

            if ($choice -ieq "E") {
                cls
                Write-host `nDisplaying users with EXPIRED passwords... -BackgroundColor White -ForegroundColor Black
                getusers('expired')
                }

            if ($choice -ieq "A") {
                cls
                getusers('showall')
                }
        
            if ($choice -ilike "Check*") {
                cls
                $choice = $choice.replace('check','').Replace(' ','')
                Try { Get-aduser -Identity $choice -Properties PasswordLastSet,PasswordExpired,PasswordNeverExpires,LastLogonDate,Enabled,Created } catch { Write-host `nUser not found. -ForegroundColor DarkRed }
                Try { $ingroup = Get-ADPrincipalGroupMembership $choice | select -ExpandProperty name } catch { $ingroup = 'NULLDATA' } 
                Write-host "`nUser in groups: " -NoNewline; Write-host $($ingroup -join ', ')`n`n -ForegroundColor Black -BackgroundColor White
                pause
                }

            if ($choice -ieq 'X') { 
                $confirm = Read-host `nType RESET again to continue. This will `nforce ALL accounts to reset password on next logon `n`n>
                cls
                if ($confirm -ieq 'reset') {
                    foreach ($u in $global:USERPWlist) { 
                        Write-host Setting PW reset flag for user [ $($u.samaccountname) ] -ForegroundColor green
                        Set-ADUser -Identity $u -CannotChangePassword:$false -PasswordNeverExpires:$false -ChangePasswordAtLogon:$true
                        }
                    getusers('normal') 
                    }     
                }

            } else {
           
                $usr = $global:USERPWlist[$choiceint -1].samaccountname
                if ($usr -ne $null -and $choiceint -ne 0) {

                    if ($choice -like '*@*') { 
                            $confirm = Read-host `nType X again to confirm. `Disable user [ $usr ] `n`n>
                            if ($confirm -ieq 'X') {
                                cls
                                Write-host DISABLING user [ $usr ] -ForegroundColor green
                                Set-AdUser -Identity $usr -Enabled 0
                                if ($global:checkadmins -eq 'NO') { getusers('normal') } else { getusers('showadmins') }
                                }                 
                        }

        
                    if ($choice -like '*`**') { 
                            $confirm = Read-host `nType X again to confirm. `nREMOVE user [ $usr ] from all ADMIN groups `n`n>
                            if ($confirm -ieq 'X') {
                                cls
                                $usrgrp = Get-ADPrincipalGroupMembership $usr | ? { $_.name -iin 'Administrators', 'Schema Admins', 'Enterprise Admins', 'Domain Admins' } | select -ExpandProperty name
                                foreach ($group in $usrgrp) {
                                    Write-host REMOVING user [ $usr ] from $group group -ForegroundColor green
                                    if ($group -eq 'Administrators') { net localgroup "$($group)" /delete $usr | out-null } else { net group "$($group)" /delete $usr | out-null }
                                    }
                                getusers('showadmins')
                                }            
                        }
                    
                    if ($choice -notlike '*`**' -and $choice -notlike '*@*') {
                        $confirm = Read-host `nType X again to confirm. `nForce [ $usr ] to reset password on next logon `n`n>
                        if ($confirm -ieq 'X') {
                            cls
                            Write-host Setting PW reset flag for user [ $usr ] -ForegroundColor green
                            Set-ADUser -Identity $usr -CannotChangePassword:$false -PasswordNeverExpires:$false -ChangePasswordAtLogon:$true
                            if ($global:checkadmins -eq 'NO') { getusers('normal') } else { getusers('showadmins') }
                            continue
                            }     
                        }  

                    } else { cls; Write-host Invalid selection`, try again...`n -ForegroundColor DarkRed; continue } 
                }

        continue

        } #While Loop
    
    } # (pwlist) Function

cls

#ulist = Check Regular users
#alist = Check Admin users
#clist = Check Computer accounts
#pwlist = Check Stale Passwords (Main Script)