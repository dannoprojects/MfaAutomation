# MfaAutomation

## Goal
Auomate MFA enablement for new hires for an O365 and On-Prem Active Directory environment using free tools.  New hires are enabled for MFA within
the first 48 hours of employment.

## Requirements
-Basic O365 Subscription using Azure AD Connect Sync (free tier)
-Active Directory
-SQLExpress instance
-PowerShell v5

## Expectations
-Before users start an account has been created in AD.
-AD account for the user is flagged with "Change Password on next login"
-When the user signs into the account and updates the password, the PasswordLastSet property is date stamped.
