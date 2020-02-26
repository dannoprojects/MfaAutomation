<#
.SYNOPSIS
Controller script for finding users in AD with PasswordLastSet equals NULL and setting a MFA data for eligible users.

.DESCRIPTION
Controller script for finding users in AD with PasswordLastSet equals NULL and setting a MFA data for eligible users.  Users are excluded from the table based on 
their home country.  Not all countries are Paige markets and must be excluded from this process.

.NOTES

#>

$Date = Get-Date -f yyyyMMddHHmm
Start-Transcript -Path "C:\mfa\Transcripts\$Date-GetNewHires.txt"

Import-Module DomainMfa

# Variables used with functions

[string]$AdServer = (Get-ADDomainController -Discover -NextClosestSite -DomainName global.com).HostName
$SQLServer = 'SQLUSIDCOPSLIS'
$SQLDatabase = 'MFA'
$ConnectionString = "Data Source=$SqlServer;Database=$SQLDatabase;Integrated Security=SSPI"
$LogTable = 'mfalog'
$MfaUserTable = 'mfainfo'

# Get users with PasswordLastSet -eq $NULL and add to DomainMfaDb.  Excludes US, GB, and CA
Get-DomainMfaEligible -IseExclusions 'US', 'GB', 'CA' -Server $AdServer -Verbose | Write-DomainmfaDb -ConnectionString $ConnectionString -MfaUserTable $MfaUserTable -Verbose

# Get users from DomainMfaDb where PasswordLast -eq $NULL and add to array
$CheckUsers = Find-DomainPLS -ConnectionString $ConnectionString -MfaUserTable $MfaUserTable -Verbose

# Use $CheckUsers array to deterine if a user has changed password, then update DomainMfaDb with PasswordLastSet to "Set"
Get-DomainAdUpdate -Identity $CheckUsers -Server $AdServer -ConnectionString $ConnectionString -LogTable $LogTable -Verbose | Update-DomainMfaPlsDb -ConnectionString $ConnectionString -MfaUserTable $MfaUserTable -Verbose

# Check Db for users that have PasswordLastSet "Set" and set a time for MFA in the future
Write-DomainMfaDate -ConnectionString $ConnectionString -MfaUserTable $MfaUserTable -MfaDate 3 -Verbose

Stop-Transcript