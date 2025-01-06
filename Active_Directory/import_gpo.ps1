#VERIFY
#!ps
#maxlength=100000
#timeout=90000
import-module grouppolicy
$currentdomain = (([string](wmic computersystem get domain)).replace('Domain','')).trim().split('.')
$linkedgpos = Get-GPInheritance -Target "dc=$($currentdomain[0]),dc=$($currentdomain[1])"
$pangpo = $linkedgpos.gpolinks | ? { $_.displayname -match 'PANUSERID'} | Select-Object displayname,target
Write-host Found $pangpo.displayname at location $pangpo.target !


#!ps
#maxlength=100000
#timeout=90000

import-module grouppolicy
$gponame = "Remote_Management_Policy"
$downloadpath = "c:\users\public\"
$downloadfile = $downloadpath + $gponame + ".zip"

if (Test-path $downloadfile) { 
	Remove-item $downloadfile 
}

iwr -Uri "http://website.com/files/$gponame.zip" -OutFile $downloadfile

if ( (Test-path $downloadfile) -eq $false) { 
	curl -o $downloadfile "http://website.com/files/$gponame.zip"
}


$guid = gci $downloadpath | ? { $_.name -match "{.*}" }

if ($guid -ne $null -and $guid -ne "") { 
#	Remove-item $guid.fullname -recurse
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

unzip $downloadfile $downloadpath

$global:currentdomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select -ExpandProperty Domain
$prefix = $currentdomain.split(".")[0]
$suffix = $currentdomain.split(".")[1]

New-GPO -Name $gponame | New-GPLink -Target "dc=$prefix,dc=$suffix" -LinkEnabled Yes 
import-gpo -BackupGpoName $gponame -TargetName $gponame -path $downloadpath -CreateIfNeeded



# RENAMING #

$discovered = (Get-ADComputer -filter 'samaccountname -like "*"' `
	| sort -Property name `
	| ft -Property NAME -HideTableHeaders -AutoSize `
	| out-string).trim().split([Environment]::NewLine).where({$_ -ne ""}) `
	| % { $_.split('-')[0] } | Group-Object | Sort-Object Count -Descending `
	| Select-Object -ExpandProperty Name -First 1
	
	
	
$discovered = (Get-ADComputer -filter 'samaccountname -like "*SERV*"' `
	| sort -Property name `
	| ? { $_.Enabled -eq $True })
	

$discovered | ft -Property NAME -HideTableHeaders -AutoSize

Rename-Computer -ComputerName "WIN11PRO-TEST" -NewName "WIN11PRO-TEST2"


$prefix = (Get-ADComputer -filter 'samaccountname -like "*"' `
	| sort -Property name `
	| ft -Property NAME -HideTableHeaders -AutoSize `
	| out-string).trim().split([Environment]::NewLine).where({$_ -ne ""}) `
	| % { $_.split('-')[0] } | Group-Object | Sort-Object Count -Descending `
	| Select-Object -ExpandProperty Name -First 1
	
Get-ADGroup Evo_MFA | Set-adgroup -Description "EVO MFA Group for domain $($prefix)" -Verbose
Get-ADGroup Evo_MFA -Properties * | Ft Name,Description

(Get-NetFirewallRule | ? {$_.DisplayName -imatch "Windows Management Instrumentation" -and $_.DisplayName -imatch "(DCOM-In)|(WMI-In)" -and $_.Profile -eq "Domain"}) | Set-NetFirewallRule -Enabled "True"