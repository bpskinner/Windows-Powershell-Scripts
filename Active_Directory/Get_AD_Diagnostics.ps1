#| Out-GridView -PassThru | Select SamAccountName

# // GET DIAGNOSTICS //

import-module activedirectory
$domain = (get-addomain -current localcomputer).forest
get-date

ipconfig /all ; "`n" 

"DIAGNOSTICS RUNNING ON SERVER! $(hostname)`n" 

"~~Getting all domain controllers~~" 
$serverlist = (Get-ADDomainController -filter * | Select-Object name,IPv4Address)
foreach ($x in $serverlist) { $x.name + " ($($x.IPv4Address))"  }

"`n~~Running NS lookup for $domain~~" 
nslookup -type=ns $domain | ? { $_ -match "nameserver|internet"} >> "$logfile"; "`n" 

"~~Performing DNS query on each server~~" 
foreach ($x in $serverlist) { nslookup wikipedia.org $x.IPv4Address   }

"`n~~Running FSMO query~~" 
netdom query fsmo ; "`n" 

"~~Checking replication service~~" 
get-service dfsr,ntfrs 
dfsrmig /getglobalstate ; "`n" 

"~~Checking replication status~~" 
repadmin /showrepl /errorsonly ; "`n" 
repadmin /replsummary ; "`n" 
repadmin /queue ; "`n" 

"~~Running DCDIAG command with errors only~~" 
dcdiag /e /q ; "`n" 

"~~Testing sysvol replication to other domain controllers FROM CURRENT SERVER, true means success~~" 
foreach ($x in $serverlist) { $x.name + " ($($x.IPv4Address))"  }
$sysvolpath = 'c:\windows\sysvol\domain\scripts'
if (test-path c:\windows\sysvol_DFSR) { $sysvolpath = 'c:\windows\sysvol_DFSR\domain\scripts' }
"
Sysvol path is ($sysvolpath)" 
new-item -path $sysvolpath -Name REPLICATION_TEST.txt -ItemType 'file' | out-null
$testfile = 'REPLICATION_TEST.txt'
sleep 10
foreach ($server in $serverlist.Name) { "$server ($(test-path $("filesystem::\\$($server.trim())\netlogon\$($testfile)"))) - $((gci -Recurse $("filesystem::\\$($server.trim())\netlogon\")).Count) files found under scripts - $((gci -Recurse $("filesystem::\\$($server.trim())\SYSVOL\$domain\Policies")).Count) files found under policies"  }; "`n `n" 
remove-item $sysvolpath\REPLICATION_TEST.txt | out-null

"~~Dumping GPO list~~" 
get-gpo -all | ft displayname,creationtime 

# // GET USER OBJECTS //
"`n`n`n`n`n"

$global:list = $null
$group = Get-ADGroupMember "domain admins" | select -ExpandProperty samaccountname

$ADusers = (Get-ADUser -filter * -Properties LastLogonDate,Created,Enabled,LastBadPasswordAttempt `
| select-object SamAccountName,LastLogonDate,Enabled,Created,LastBadPasswordAttempt) `
| ? { $_.Enabled -eq $True -and $_.samaccountname -inotin $allowedusers }
    
Foreach ($user in $ADusers) { 

    if ($user.LastLogonDate -eq $null -and (NEW-TIMESPAN –End $(get-date) –Start $user.Created).TotalDays -gt 60) { 
        if ($group -notcontains $user.samaccountname) {
            [array]$global:list += $user
        }
    }

    if ($user.LastLogonDate -ne $null -and (NEW-TIMESPAN –End $(get-date) –Start $user.lastlogondate).TotalDays -gt 60) { 
        if ($group -notcontains $user.samaccountname) {
                [array]$global:list += $user
        }
    }

}

$global:list = $global:list | Sort-Object -Descending -Property LastLogonDate,Created

Write-host "`nListing users that haven't logged in for more than 60 Days..." -BackgroundColor DarkYellow -ForegroundColor Black
Write-host "`n    | User                      | LastLogon | First Created" -ForegroundColor DarkGray
Write-host "    \_________________________________________________/`n" -ForegroundColor DarkGray
        
$i = 0
foreach ($x in $global:list) {
    $i += 1
    try { $lastlogon = ($x.LastLogonDate).tostring('MM-dd-yy') } catch { $lastlogon = 'NULLDATE' }
    Write-host $("   $i>" + ' ' * (4 - ([string]$i).length)) -NoNewline; write-host $($x.samaccountname + ' ' * (23 - ($x.samaccountname).Length))   ' | ' $($lastlogon) "|" $(($x.Created).tostring('MM-dd-yy'))  -ForegroundColor Red 
} 
            
"`n`n`n"

# // GET COMPUTER OBJECTS //

$global:complist = $null

$ADcomputers = Get-ADComputer -Filter "CN -like '*'" -Properties CN,LastLogonDate,Created,Enabled

foreach ($PC in $ADcomputers) { 
    if ($PC.LastLogonDate -eq $null) { 
        [array]$global:complist += $PC 
        continue
    }
    if ($PC.Enabled -eq $True -and (NEW-TIMESPAN –End $(get-date) –Start $PC.LastLogonDate).TotalDays -gt 45) {
        [array]$global:complist += $PC 
        continue
    }
    if ((NEW-TIMESPAN –End $(get-date) –Start $PC.LastLogonDate).TotalDays -gt 150) {
        [array]$global:complist += $PC 
        continue
    }
}
    
$global:complist = $global:complist | Sort-Object -Descending -Property LastLogonDate,Created

Write-host "`nInitial computer count is < $(($ADcomputers | ? { $_.Enabled -eq $True } ).count) >" -ForegroundColor DarkYellow
Write-host Listing all computer accounts unused for over 45 days... -BackgroundColor DarkYellow -ForegroundColor Black
Write-host "`n    | Computer                  | LastLogon | First Created" -ForegroundColor DarkGray
Write-host "    \_________________________________________________/`n" -ForegroundColor DarkGray
        
$i = 0
foreach ($x in $global:complist) {
    $i += 1
    try { $lastlogon = ($x.LastLogonDate).tostring('MM-dd-yy') } catch { $lastlogon = 'NULLDATE' }
    $cn = $x.cn.split("`n") | select -Index 0
    Write-host $("   $i>" + ' ' * (4 - ([string]$i).length)) -NoNewline; write-host $($cn + ' ' * (23 - ($cn).Length) + ' | ') $($lastlogon) "|" $(($x.Created).tostring('MM-dd-yy')) -ForegroundColor Red 
} 

"`n`n`n"

# // GET PASSWORDS //

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

    $global:USERPWlist = $global:USERPWlist | Sort-Object -Descending -Property LastLogonDate

} #getusers

function enumerate($list) {
        
    Write-host "`n        User                 | PW Last Set | PW Expired | Nvr Expires | Last Logon | Enabled" -ForegroundColor DarkGray
    Write-host "        \__________________________________________________________________________________/" -ForegroundColor DarkGray
        
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

$global:USERPWlist = $null
$global:admingroup = $null
$global:ADusers = $null
    
$global:showgeneric = 'NO'
$global:checkadmins = 'NO'
$global:ADusers = updateusers
$global:admingroup = updateadmins

sleep 1
getusers('showall')
Write-host "`nListing users with Passwords older than 60 days..." -BackgroundColor DarkYellow -ForegroundColor Black 
enumerate($global:USERPWlist) 
Write-host `n`(`"*`" = Admin User`, `"[]`" = Generic User`, Dark Yellow = Older than 90 days`) -ForegroundColor DarkGray 
"`n`n`n`n`n"