$runningasadmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($runningasadmin -eq $false) {
    write-host Launching as Administrator! -ForegroundColor Red
    Start-Sleep 1
    start-process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass $PSCommandPath"
    exit
}

function output-to-csv {
    param(
        [string]$Filename,
        [array]$list
    )

    #Defaults to user desktop:
    $Folder = "$env:USERPROFILE\desktop"
    $path = "$Folder\$Filename"

    #Grabs each unique column from the entire list of firewall outputs. This is important since some firewalls may have more columns of data than others.
    #When exporting to a CSV, the columns are initialized with the first object that's exported to the file.
    #If any object proceeding the first contain more data (or different column names), they will be truncated.
    #This is why we grab the total unique columns in the previous variable.
    $getcolumns = $list | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique

    #Initializes CSV with complete column list.
    {} | Select $getcolumns | Export-Csv $path -NoTypeInformation -Force

    #Finally, dump all data into the CSV.
    $list | ForEach-Object { Export-Csv $path -InputObject $_ -append -NoTypeInformation -Force }
}

function parse_users {
    param(
        [Parameter(mandatory=$true)]
        [array]$list
        )
    
    $global:collection = @()
    
    foreach ($user in $list) { 
        $search = get-adprincipalgroupmembership -Identity ($user).samaccountname | Select-Object Name
        if ($checkallgroups -ne 1) { $search = $search | Where-object {$_ -notmatch ($nonPANgroups -join "|")} } 

        $state = ($user.DistinguishedName).split(",").where({$_ -match 'OU' -and $_ -notmatch 'People' -and $_ -notmatch '_'}).replace('OU=','') | Select-Object -Last 1
        $location = ($user.DistinguishedName).split(",").where({$_ -match 'OU' -and $_ -notmatch 'People'}).replace('OU=','') | Select-Object -First 1
        
        $user_meta = [PSCustomObject]@{
            State           = $state
            Location        = $location
            Full_Name       = $user.Name
            Account         = $user.SamaccountName
            Description     = $user.Description
            Groups          = $(($search.name) -join ', ')
            #Enabled         = $user.enabled
            Last_Logon      = $user.LastLogonDate
            Expiration      = $user.AccountExpirationDate
            First_Created   = $user.Created
            Pwd_Last_Set    = $user.PasswordLastSet
            Pwd_Nvr_Expires = $user.PasswordNeverExpires
            Pwd_Expired     = $user.PasswordExpired
            }
        
        Write-host [Processed user $($list.IndexOf($user)) of $($list.Length)]
        $user_meta

        $global:collection += $user_meta
    }
}

#Initialize import modules and variables:
import-module activedirectory
$DOMAIN = ($env:userdnsdomain).split('.').trim()

#Groups that aren't normally used in Palo security policies:
$nonPANgroups = "domain admins", "domain users", "enterprise admins", "Schema Admins", "DHCP Administrators", "Remote Desktop Users","Server Operators","Administrators","Group Policy Creator Owners"
$checkallgroups = 0 #0 for no, 1 for yes

#Root OU to search within:
$ou = "People"

#Gather AD User properties:
$enabledusers = Get-ADUser -filter 'enabled -eq $true' -SearchBase "OU=$ou,DC=$($DOMAIN[0]),DC=$($DOMAIN[1])" `
-Properties Enabled,name,SamaccountName,AccountExpirationDate,cn,Created,PasswordNeverExpires,PasswordLastSet,PasswordExpired,LastLogonDate,Description,DistinguishedName

#Output location:
parse_users -list $enabledusers # -> Sets collection variable globally
output-to-csv -filename 'User_AD_Audit.csv' -list $collection