# MfaAutomation
## Background
My organization needed to automate MFA for all new hires within 48 hours of the employee starting.  One of the challenges was figuring out when 
a user actually starts.  I decided to to use the AD property PasswordLastSet to really determine when a user has started and collected their device.
When the account is set to 'Change password on next login' the property PasswordLastSet is empty.  When the password is set, the property is datestamped.  Using this with accounts created within the last 30 days is a good indicator of new users.  We also use a number of custom attributes in our environment.

## Goal
Auomate MFA enablement for new hires for an O365 and On-Prem Active Directory environment using free tools.  New hires are enabled for MFA within
the first 48 hours of employment.  Users are emailed a notification to finalize their MFA after the first login.

## Requirements
- Basic O365 Subscription using Azure AD Connect Sync (free tier)
- Active Directory
- SQLExpress instance
- PowerShell v5

## Expectations
- Before users start an account has been created in AD.
- AD account for the user is flagged with "Change Password on next login"
- When the user signs into the account and updates the password, the PasswordLastSet property is date stamped.
