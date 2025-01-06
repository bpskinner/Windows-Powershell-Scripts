$Username   = Read-host Enter your Microsoft Admin email

Connect-MsolService

$AllTenants = (Get-MsolPartnerContract -All | Select-Object DefaultDomainName, Name, TenantId)

do {
    
    $AllTenants | ft
    Write-host "Please select a Tenant"
    $SelectedTenant = Read-host ->
    
    $Tenant = $AllTenants | Where-Object { $_.Name -match $SelectedTenant -or $_.DefaultDomainName -match $SelectedTenant } | select -First 1
    
    cls
    $Tenant | ft
    Write-host `
        "
        Confirm selection?
        Y for Yes
        N for No
        "

    $confirm = Read-host ->

} until ($confirm -ieq 'y')

Connect-ExchangeOnline -DelegatedOrganization $Tenant.DefaultDomainName -UserPrincipalName $Username
#Connect-MgGraph -TenantId $Tenant.TenantId
"Finding Azure Active Directory Accounts..."

$Users = Get-Mailbox | select UserPrincipalName
$Report = [System.Collections.Generic.List[Object]]::new() # Create output file
Write-Host "Processing" $Users.Count "accounts..." 

ForEach ($User in $Users) {
    $Enabled = [Boolean](Get-mailbox $user_email -ErrorAction SilentlyContinue)
    $User_Email           =  $user.UserPrincipalName
    $mailbox              = try { Join-Object -LeftObject (Get-Mailbox $User_Email) -RightObject (Get-MailboxStatistics $User_Email) } catch { "No_Mailbox" }

    $OrgRoot              = $mailbox.OrganizationalUnitRoot
    $MFADefaultMethod     = ($User.StrongAuthenticationMethods | Where-Object { $_.IsDefault -eq "True" }).MethodType
    $MFAPhoneNumber       = $User.StrongAuthenticationUserDetails.PhoneNumber
    $PrimarySMTP          = $mailbox.PrimarySmtpAddress -replace "SMTP:", ""
    $Aliases              = $mailbox.EmailAddresses | Where-Object { $_ -ilike "smtp*" -and $_ -notmatch $PrimarySMTP } | ForEach-Object { $_ -replace "smtp:", "" }
    $Licensed             = $User.IsLicensed #Added line (bskinner)
    #$LicenseDetail        = (Get-MgUserLicenseDetail -UserId $User_Email).SkuPartNumber -join ', '
    #$LastPasswordChange   = ([Datetime]($User.LastPasswordChangeTimestamp)).ToString('MM-dd-yyyy')
    $PasswordExpires      = $User.PasswordNeverExpires
    $WhenCreated          = ([Datetime]($mailbox.WhenMailboxCreated)).ToString('MM-dd-yyyy')
    $IsQuarantined        = $mailbox.IsQuarantined
    $IsArchive            = $mailbox.IsArchiveMailbox
    $LastLogonTime        = $mailbox.LastLogonTime
    $LastInteractionTime  = $mailbox.LastInteractionTime
    $LastActionTime       = $mailbox.LastUserActionTime
    $MailboxSize          = $mailbox.TotalItemSize
    $MailboxType          = $mailbox.MailboxTypeDetail
    $MailboxForward       = ($mailbox).ForwardingSmtpAddress -join ', '
    $LigitationHold       = $mailbox.LitigationHoldEnabled

    if ($MailboxForward -ne $null) {
        $MailboxForward   = $MailboxForward.replace('smtp:','')
    }

    If ($User.StrongAuthenticationRequirements) {
        $MFAState = $User.StrongAuthenticationRequirements.State
    }
    Else {
        $MFAState = 'Disabled'
    }

    If ($MFADefaultMethod) {
        Switch ($MFADefaultMethod) {
            "OneWaySMS" { $MFADefaultMethod = "Text code authentication phone" }
            "TwoWayVoiceMobile" { $MFADefaultMethod = "Call authentication phone" }
            "TwoWayVoiceOffice" { $MFADefaultMethod = "Call office phone" }
            "PhoneAppOTP" { $MFADefaultMethod = "Authenticator app or hardware token" }
            "PhoneAppNotification" { $MFADefaultMethod = "Microsoft authenticator app" }
        }
    }
    Else {
        $MFADefaultMethod = "Not enabled"
    }
  
    $ReportLine = [PSCustomObject] @{
        UserPrincipalName  = $User.UserPrincipalName
        DisplayName        = $User.DisplayName
        License            = $Licensed
        LicenseDetail      = $LicenseDetail
        MFAState           = $MFAState
        MFADefaultMethod   = $MFADefaultMethod
        MFAPhoneNumber     = $MFAPhoneNumber
        PrimarySMTP        = ($PrimarySMTP -join ', ')
        Aliases            = ($Aliases -join ', ')
        LastPasswordChange = $LastPasswordChange
        PasswordExpires    = $PasswordExpires
        LitigationHold     = $LigitationHold
        IsQuarantined      = $IsQuarantined
        IsArchive          = $IsArchive
        LastLogonTime      = $LastLogonTime
        LastInteractionTime= $LastInteractionTime
        LastActionTime     = $LastActionTime
        MailboxSize        = $MailboxSize
        MailboxType        = $MailboxType
        MailboxForward     = $MailboxForward
    }
    
    $ReportLine
    $Report.Add($ReportLine)
}

Write-Host "Report is in c:\temp\MFAUsers.csv"
$Report | Sort-Object UserPrincipalName | Out-GridView
$Report | Sort-Object UserPrincipalName | Export-CSV -Encoding UTF8 -NoTypeInformation c:\temp\MFAUsers.csv