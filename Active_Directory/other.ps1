
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
# #!PS
# (Get-NetFirewallRule | ? {$_.DisplayName -imatch "Windows Management Instrumentation" -and $_.DisplayName -imatch "(DCOM-In)|(WMI-In)" -and $_.Profile -imatch "Domain|Private"}) | Set-NetFirewallRule -Enabled "True"
# (Get-NetFirewallRule | ? {$_.DisplayName -imatch "Windows Management Instrumentation" -and $_.DisplayName -imatch "(DCOM-In)|(WMI-In)" -and $_.Profile -imatch "Domain|Private"}) | select Displayname,Enabled