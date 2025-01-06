$ComputerNewName     = "MBN-TABLET01"
$domainadminusername = ""
$domainadminpassword = "" `
| ConvertTo-SecureString -AsPlainText -Force 

$credentials = new-object System.Management.Automation.PSCredential($domainadminusername,$domainadminpassword) 
Rename-Computer -NewName $ComputerNewName -DomainCredential $credentials -force -Verbose