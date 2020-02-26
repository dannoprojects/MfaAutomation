<#
.SYNOPSIS
Controller script for enabling MFA for users, emailing notifications, and performing database maintainence.

.DESCRIPTION
Controller script for enabling MFA for users, emailing notifications, and peforming database maintainence.

.NOTES

#>

Import-Module DomainMfa

$Date = Get-Date -f yyyyMMddHHmm
Start-Transcript -Path "C:\mfa\Transcripts\$Date-MFAEnablement.txt"

$SQLServer = 'SQLUSIDCOPSLIS'
$SQLDatabase = 'MFA'
$ConnectionString = "Data Source=$SqlServer;Database=$SQLDatabase;Integrated Security=SSPI"
$LogTable = 'mfalog'
$MfaUserTable = 'mfainfo'

# Connect to O365
$ServiceAccount = ""
$TenantPass = cat "C:\txtfile.txt" | ConvertTo-SecureString
$TenantCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ServiceAccount, $TenantPass
$msoExchangeURL = �https://ps.outlook.com/powershell/�
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $msoExchangeURL -Credential $TenantCredentials -Authentication Basic -AllowRedirection 
Import-PSSession $session
Connect-MSOLService -Credential $TenantCredentials

#Get users from DomainMfaDb that have an enablement date of TODAY
$MfaReady = Get-DomainMfaReady -ConnectionString $ConnectionString -Verbose

ForEach($User in $MfaReady)
{
    # Verify MFA status for users. Log Successes, Warnings, and Failures as needed.
    try
    {
        $MfaStatus = Get-DomainMfa -UserPrincipalName $User.UserPrincipalName -ErrorAction Stop

        If ($MfaStatus.MfaStatus -eq 'NotSet')
        {
            try
            {
                Set-DomainMfa -UserPrincipalName $User.UserPrincipalName -ErrorAction Stop
                Write-Host "$($User.UserPrincipalName) MFA Enabled"
    
                $MfaSuccess = @{
                    Type = "Success"
                    Source = "Set-DomainMfa"
                    Description = "MFA set successfully"
                    UserID = "$($User.UserPrincipalName)"
                    Country = "$($User.Country)"
                }
    
                New-DomainEventObject @MfaSuccess | Write-DomainMfaLog -ConnectionString $ConnectionString -LogTable $LogTable
            }# end try
            
            catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException]
            {
                $MsolUserError = $_.Exception.Message 
                if ($MsolUserError -match "^User Not Found.")
                {
                    $MsolUserFound = $false
                }
    
                else 
                {
                    throw
                }
    
                $NoUserInCloud = @{
                    Type = "Failure"
                    Source = "Get-DomainMfa"
                    Description = "User not found in the O365 tenant"
                    UserID = "$($User.UserPrincipalName)"
                    Country = "$($User.Country)"
                }
                New-DomainEventObject @NoUserInCloud | Write-DomainMfaLog -LogTable $LogTable -ConnectionString $ConnectionString
            }# end catch
        }# End If
        Else 
        {
            Write-Verbose "$($User.UserPrincipalName) MFA already enabled"
            $MfaAlreadyEnabled = @{
                Type = "Warning"
                Source = "Get-DomainMfa"
                Description = "MFA already set for user."
                UserID = "$($User.UserPrincipalName)"
                Country = "$($User.Country)"
            }
            New-DomainEventObject @MfaAlreadyEnabled | Write-DomainMfaLog -ConnectionString $ConnectionString -LogTable $LogTable
        }
    }
    # Catch users not in the cloud
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException]
    {
        $MsolUserError = $_.Exception.Message 
        if ($MsolUserError -match "^User Not Found.")
        {
            $MsolUserFound = $false
        }
        else 
        {
            throw
        }

        # Log users not in cloud
        $NoUserInCloud = @{
            Type = "Failure"
            Source = "Set-DomainMfa"
            Description = "User not found in the O365 tenant"
            UserID = "$($User.UserPrincipalName)"
            Country = "$($User.Country)"
        }
        New-DomainEventObject @NoUserInCloud | Write-DomainMfaLog -LogTable $LogTable -ConnectionString $ConnectionString
    }    
}

# Notify users of MFA enablement
$UsersToNotify = Get-DomainMfaEmailNotice -ConnectionString $ConnectionString -MfaUserTable $MfaUserTable -Verbose

ForEach ($User in $UsersToNotify)
{
    $MailProps = @{
        To = "$($User.UserPrincipalName)"
        From = 'Domain Technology <no-reply@oneDomain.com>'
        Subject = "Microsoft Multi-Factor Authentication (MFA)Starts Tomorrow!"
        Attachments = 'C:\mfa\EmailFiles\MFA Enrollment Guide - Windows 10.pdf',  'C:\MFA\EmailFiles\MFA Enrollment Guide - Windows 7 and Mac.pdf'
        SmtpServer = "naidcexchange"
        Body = Get-Content 'C:\MFA\emailfiles\mfa-email.html' | Out-String
        BodyAsHTML = $true
    }
    
    Send-MailMessage @MailProps
    
    #Write an event to the log table
    $UserNotification = @{
        Type = "Success"
        Source = "MFA Notification"
        Description = "$($User.UserPrincipalName) emailed MFA notification"
        UserID ="$($User.UserPrincipalName)"
        Country = "$($User.Country)"
    }
    New-DomainEventObject @UserNotification | Write-DomainMfaLog -ConnectionString $ConnectionString -LogTable $LogTable
}

Stop-Transcript