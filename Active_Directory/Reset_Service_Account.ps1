
#Reset local service account passwords
$Service = Get-WmiObject -Class Win32_Service -Filter  "StartName LIKE '%KASQLEXPRESS%'"
$Password = Read-Host -Prompt "Enter password for $RunAsAccount" -AsSecureString
$BSTR = [system.runtime.interopservices.marshal]::SecureStringToBSTR($Password)
$Password = [system.runtime.interopservices.marshal]::PtrToStringAuto($BSTR)
$Service.Change($Null,$Null,$Null,$Null,$Null,$Null,$Null,$Password,$Null,$Null,$Null) 
$Service.StopService().ReturnValue
$Service.StartService().ReturnValue


$Service | Get-Member -MemberType  Method 


# https://mcpmag.com/articles/2015/01/22/password-for-a-service-account-in-powershell.aspx