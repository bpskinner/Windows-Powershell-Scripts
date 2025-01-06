Install-Module azureadpreview -Force
Import-Module azureadpreview -Force
Install-Module Microsoft.Graph -Force
Import-Module Microsoft.Graph -Force
Connect-AzureAD

function Request-AzureToken {
    $ApplicationID    = "APPID"
    $DirectoryID      = "DID"
    $ClientSec        = ""

    $Body = @{    
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        client_Id     = $ApplicationID
        Client_Secret = $ClientSec
    } 

    $ConnectGraph = Invoke-RestMethod `
    -Uri "https://login.microsoftonline.com/$DirectoryID/oauth2/v2.0/token" `
    -Method POST `
    -Body $Body

    $token = $ConnectGraph.access_token

    $AuthHeader = @{
    'Authorization'="Bearer $($token)"
    }
    return $AuthHeader
}

function Get-AzureInactiveUsers {
    param(
        [Parameter(mandatory=$false)]
        [int]$LastLogonDays="30",
        [Parameter(Mandatory=$false)]
        [string]$CSVFileName = "AzureAD_Last_Logon.csv"
    )

    $Auth = Request-AzureToken

    $Days = (get-date).adddays(-$LastLogonDays)
    $GraphDays = $Days.ToString("yyyy-MM-ddTHH:mm:ssZ")

    $LoginUrl = 'https://graph.microsoft.com/beta/users?$select=displayName,userPrincipalName,signInActivity'
    #$LoginUrl = "https://graph.microsoft.com/v1.0/sites"
    $WebReq = Invoke-RestMethod -Headers $Auth -Uri $LoginUrl
    $Result = ($WebReq).Value

    $ExpiredUsers | FT DisplayName,Mail,userType,userPrincipalName,JobTitle,accountEnabled,department,companyName,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSyncEnabled,createdDateTime
    $ExpiredUsers | Select-Object DisplayName,Mail,userType,userPrincipalName,JobTitle,accountEnabled,department,companyName,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSyncEnabled,createdDateTime `
    | Export-Csv $CSVFileName
    $ExpiredUsers.count
}


$ClientID    = "CID"
$TenantID      = "TID"
$ClientSecret     = "secret"

Connect-MgGraph -ClientId $ClientID -TenantId $TenantID -CertificateThumbprint $ClientSecret

$Properties = @(
    'Id','DisplayName','UserPrincipalName','UserType', 'AccountEnabled', 'SignInActivity'   
)
 
 Get-AzureADUser -All
$AllUsers =  Get-AzureADUser -All
 
$SigninLogs = @()
ForEach ($User in $AllUsers)
{
    $SigninLogs += [PSCustomObject][ordered]@{
            LoginName       = $User.UserPrincipalName
            DisplayName     = $User.DisplayName
            UserType        = $User.UserType
            AccountEnabled  = $User.AccountEnabled
            LastSignIn      = $User.SignInActivity.LastSignInDateTime
    }
}
 

$Users = Get-MgUser
$Report = [System.Collections.Generic.List[Object]]::new() # Create output file
Write-Host "Processing" $Users.Count "accounts..." 
ForEach ($User in $Users) {
    $upn = $User.UserPrincipalName.ToLower().Trim()
    $filter = "userPrincipalName eq '" + $upn + "'"
    $Result = Get-AzureADAuditSignInLogs -Filter $filter -Top 1 | Select-Object CreatedDateTime, UserPrincipalName
    $Result
    Pause
}