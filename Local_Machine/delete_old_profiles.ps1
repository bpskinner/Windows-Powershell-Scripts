$days = 90
Write-Warning "Filtering for user profiles older than $Days days" 
Get-CimInstance win32_userprofile | 
Where {$_.LastUseTime -lt $(Get-Date).Date.AddDays(-$days)} |
Remove-CimInstance -Verbose