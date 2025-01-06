$user_list = $null
$When = ((Get-Date).AddDays(-90)).Date  
$GetUser = Get-ADUser -Filter {(LastLogonDate -lt $When -or LastLogonDate -notlike "*")} -Properties samaccountname,givenname,surname,LastLogonDate
$GetUser | Foreach-Object {
    $user = [PSCustomObject]@{
        Samaccountname = $_.samaccountname
        Fullname       = "$($_.givenname) $($_.surname)"
        Groups         = (Get-ADPrincipalGroupMembership $_.samaccountname).name -join ', '
        LastLogon      = if ($_.LastLogonDate -ne $null) { $_.LastLogonDate } else { "NOT FOUND" }
    }
    $user
    [Array]$user_list += $user
}
cls
$user_list | Sort-Object -Property LastLogon