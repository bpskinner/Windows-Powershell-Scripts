
# $discovered = (Get-ADComputer -filter 'samaccountname -like "*"' `
# 	| sort -Property name `
# 	| ft -Property NAME -HideTableHeaders -AutoSize `
# 	| out-string).trim().split([Environment]::NewLine).where({$_ -ne ""}) `
# 	| % { $_.split('-')[0] } | Group-Object | Sort-Object Count -Descending `
# 	| Select-Object -ExpandProperty Name -First 1
# 	
# Get-ADGroup Evo_MFA | Set-adgroup -Description "EVO MFA Group for domain $($prefix)" -Verbose
# Get-ADGroup Evo_MFA -Properties * | Ft Name,Description
# 
 #!PS
(Get-NetFirewallRule | ? {$_.DisplayName -imatch "Windows Management Instrumentation" -and $_.DisplayName -imatch "(DCOM-In)|(WMI-In)" -and $_.Profile -imatch "Domain|Private"}) | Set-NetFirewallRule -Enabled "True"
 (Get-NetFirewallRule | ? {$_.DisplayName -imatch "Windows Management Instrumentation" -and $_.DisplayName -imatch "(DCOM-In)|(WMI-In)" -and $_.Profile -imatch "Domain|Private"}) | select Displayname,Enabled


#VERIFY
#!ps
#maxlength=100000
#timeout=90000
import-module grouppolicy
$currentdomain = (([string](wmic computersystem get domain)).replace('Domain','')).trim().split('.')
$linkedgpos = Get-GPInheritance -Target "dc=$($currentdomain[0]),dc=$($currentdomain[1])"
$pangpo = $linkedgpos.gpolinks | ? { $_.displayname -match 'PANUSERID'} | Select-Object displayname,target
Write-host Found $pangpo.displayname at location $pangpo.target !




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