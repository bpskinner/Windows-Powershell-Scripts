Write-host Please select a save location!

function Get-Folder {
    if (!$folder) { 
        Write-host Select output location! -ForegroundColor Red
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog `
        -Property @{ 
            SelectedPath  = [Environment]::GetFolderPath('Desktop') 
            }
        $null = $FolderBrowser.ShowDialog()
        return $FolderBrowser.SelectedPath
    }
}

$folder = Get-Folder

Connect-MsolService
Connect-ExchangeOnline
"Finding Azure Active Directory Accounts..."

$Users = Get-MsolUser -All | Where-Object { $_.UserType -ne "Guest" -and $_.isLicensed -eq $true}
$Report = [System.Collections.Generic.List[Object]]::new() # Create output file
Write-Host "Processing" $Users.Count "accounts..." 

ForEach ($User in $Users) {
    $mailboxstats = Get-MailboxStatistics -Identity $user.UserPrincipalName
    $mailbox      = Get-Mailbox           -Identity $user.UserPrincipalName

    $MFADefaultMethod     = ($User.StrongAuthenticationMethods | Where-Object { $_.IsDefault -eq "True" }).MethodType
    $MFAPhoneNumber       = $User.StrongAuthenticationUserDetails.PhoneNumber
    $PrimarySMTP          = $User.ProxyAddresses | Where-Object { $_ -clike "SMTP*" } | ForEach-Object { $_ -replace "SMTP:", "" }
    $Aliases              = $User.ProxyAddresses | Where-Object { $_ -clike "smtp*" } | ForEach-Object { $_ -replace "smtp:", "" }
    $Licensed             = $User.IsLicensed #Added line (bskinner)
    $LicenseDetail        = ($User.Licenses | Select-Object -ExpandProperty AccountSkuId).split(':')[1]
    $LastPasswordChange   = ([Datetime]($User.LastPasswordChangeTimestamp)).ToString('MM-dd-yyyy')
    $PasswordExpires      = $User.PasswordNeverExpires
    $IsQuarantined        = $mailboxstats.IsQuarantined
    $IsArchive            = $mailboxstats.IsArchiveMailbox
    $LastLogonTime        = $mailboxstats.LastLogonTime
    $LastInteractionTime  = $mailboxstats.LastInteractionTime
    $LastActionTime       = $mailboxstats.LastUserActionTime
    $MailboxSize          = $mailboxstats.TotalItemSize
    $MailboxType          = $mailboxstats.MailboxTypeDetail
    $MailboxForward       = ($mailbox).ForwardingSmtpAddress -join ', '
    $LigitationHold       = $mailboxstats.LitigationHoldEnabled

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

Write-Host "Report is in $folder\MFAUsers.csv"
$Report | Sort-Object UserPrincipalName | Out-GridView
$Report | Sort-Object UserPrincipalName | Export-CSV -Encoding UTF8 -NoTypeInformation "$folder\MFAUsers.csv"