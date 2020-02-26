<#
.Synopsis
Manage MFA and MFA automation through a set of functions.

.Description
Module manages MFA and MFA automation throught a set of fuctions.  Functions are designed to accept input through the pipeline and produce output object.
For full use of this module a SQL database and two table are required to factilitate MFA automation. 

.Notes
Created by:  Dan Rowe, OmnicomMediaGroup

#>

function Set-DomainMfa
{
<#
.Synopsis
Enables MFA on a MSOL user object.

.Description
Enables MFA on a MSOL user object.  Cmdlet supports pipeline and assignments through an array.

.Parameter UserPrincipalName
One or more UserPrincipalName(s) as an array.

.Inputs
UserPrincipalName by pipeline or propertyname.

.Outputs
None

.Example 
Set-DomainMfa -UserPrincipalName user@domain.com
Sets MFA to enabled on user object user@domain.com

.Example
Set-DomainMfa -UserPrincipalName (Get-Content -path FilePath)
Sets MFA to enabled on an array of user objects from a plaintext file.

.Example
Get-MsolUser -SearchString 'SEARCHSTRING' | Set-DomainMfa
Pipeline input from Get-MsolUser to Set-DomainMfa.  All user objects matching the search string will have MFA enabled.

.Notes

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string[]]$UserPrincipalName
    )

    BEGIN{}

    PROCESS
    {
        ForEach ($User in $UserPrincipalName)
        {
            Write-Verbose "Enabling MFA for $User"
            $auth = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
            $auth.RelyingParty = "*"
            $auth.State = "Enabled"
            $auth.RememberDevicesNotIssuedBefore = (Get-Date)

            Set-MsolUser -UserPrincipalName $User -StrongAuthenticationRequirements $auth
        }
    }
    END{}
}

function Remove-DomainMfa
{
<#
.Synopsis
Removes MFA from a MSOL user object.

.Description
Removes MFA from a MSOL user object.  Cmdlet supports pipeline and parameter input. 

.Parameter UserPrincipalName
One or more UserPrincipalName(s) as an array.

.Inputs
UserPrincipalName by pipeline or propertyname.

.Outputs
None

.Example 
Remove-DomainMfa -UserPrincipalName user@domain.com
Removes MFA on user object user@domain.com

.Example
Remove-DomainMfa -UserPrincipalName (Get-content -path FilePath)
Removes MFA on an array of user objects from a plaintext file.

.Example
Get-MsolUser -SearchString String | Remove-DomainMfa
Pipeline input from Get-MsolUser to Set-DomainMfa.  All user objects matching the search string will have MFA removed.

.Notes

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string[]]$UserPrincipalName
    )

    BEGIN{}

    PROCESS
    {
        ForEach ($User in $UserPrincipalName)
        {
            Write-Verbose "Removing MFA from $User"
            $Sta = @()
            Set-MsolUser -UserPrincipalName $User -StrongAuthenticationRequirements $Sta
        }
    }
    END{}
}

function Get-DomainMfa
{
<#
.Synopsis
Returns MFA status on a MSOL user object or objects

.Description
Returns MFA status on a MSOL user object or objects.  City and Country are also returned.  Cmdlet supports pipeline and parameter input. Cmdlet also
supports retrieving MFA status on all user objects in the tenant. 

.Parameter UserPrincipalName
One or more UserPrincipalName(s) as an array.

.Outputs
Object with UserPrincipalName, Country, City, and MFA Status

.Example 
Get-DomainMfa -UserPrincipalName user@domain.com
Returns MFA status on MSOL user object or objects.

.Example
Get-DomainMfa -UserPrincipalName (Get-content -path FilePath)
Returns MFA status on MSOL user objects from plain text file.  

.Example
Get-MsolUser -SearchString String | Get-DomainMfa
Pipeline input from a search string.  All objects found through the search string will have the status output.

.Parameter All
Used to return the MFA status of all user objects in the tenant.

.Example
Get-OmfMfa -All
Returns the MFA status on all MSOL user objects.

.Example
Get-DomainMfa -UserPrincipalName 'user'

.Notes

#>    
    [CmdletBinding()]
    Param
    (
    [Parameter(Mandatory=$true,
        ParameterSetName='All')]
    [switch]$All,

    [Parameter(Mandatory=$true,
        ParameterSetName='$UserPrincipalName',
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
    [string[]]$UserPrincipalName
    )

    BEGIN {}

    PROCESS
    {
        if ($All)
        {
            Write-Warning 'Getting MFA Status on all MSOL user objects in the tenant.'
            Write-Warning  'The operation may take several minutes to complete.'
            $MfaUsers = @()
            $AllUsers = Get-MsolUser -All

            foreach ($User in $AllUsers)
            {
                $UserMfaObj = New-Object psobject
                Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name UserPrincipalName -Value $User.UserPrincipalName
                Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name Country -Value $User.UsageLocation
                Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name City -Value $User.City
                            
                [bool]$UserMfaStatus = (($User.StrongAuthenticationRequirements.State -ne 'Enforced') -or ($User.StrongAuthenticationRequirements.State -ne 'Enabled'))
                if (($UserMfaStatus))
                {
                    Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name MFA_Status -Value 'NotSet'
                }
                else
                {
                    Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name  MfaStatus -Value $User.StrongAuthenticationRequirements.State
                }
                $MfaUsers += $UserMfaObj
            }     
        }
        else
        {
            foreach ($User in $UserPrincipalName)
            {    
                Write-Verbose "Getting MFA Status on $User"
                $UserMFAObj = New-Object psobject
                
                $UserMfa = Get-MsolUser -UserPrincipalName $User -ErrorAction Stop
                Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name UserPrincipalName -Value $User
                Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name Country -Value $UserMfa.UsageLocation
                Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name City -Value $UserMfa.City
                
                [bool]$UserMfaStatus = (($UserMfa.StrongAuthenticationRequirements.State -eq 'Enforced') -or ($UserMfa.StrongAuthenticationRequirements.State -eq 'Enabled'))
                if($UserMfaStatus)
                {
                    Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name  MfaStatus -Value $UserMfa.StrongAuthenticationRequirements.State
                }
                else
                {
                    Add-Member -InputObject $UserMfaObj -MemberType NoteProperty -Name  MfaStatus -Value 'NotSet'
                }
                $UserMFAObj
            }
        }
    }
    END{}
}

function Find-DomainPLS 
{
<#
.SYNOPSIS
 Finds users in SQL table with PasswordLastSet value is NULL

.DESCRIPTION
 Finds users in SQL table with PasswordLastSet value is NULL.  Custom object is created with all fields from the SQL table.  
 This function is used in conjection with Get-DomainAdUpdate to monitor PasswordLastSet value.

.PARAMETER ConnectionString
ConnectionString used for the SQL table

.PARAMETER MfaUserTable
User table for tracking users

.INPUTS
None

.OUTPUTS
Custom object with the following fields: SamAccountName, UserPrincipalName,StreetAddress,Country,PasswordLastSet,MfaDate

.NOTES

.EXAMPLE
Find-DomainPLS -ConnectionString 'ConnectionString' -MfaUserTable 'UserTable'
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [string]$MfaUserTable
    )
    
    BEGIN
    {
        Write-Verbose "Getting users from SQL with PasswordLastSet value equals 'NotSet'"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn
        [string] $SQLQuery= $("SELECT * FROM $MfaUserTable WHERE PasswordLastSet = 'NotSet'")
    }
    
    PROCESS 
    {
        $Cmd.CommandText = $SQLQuery
        $Reader = $Cmd.ExecuteReader()

        while ($Reader.Read()) 
        {
            
            $props = @{'SamAccountName' = $reader['SamAccountName']
            'UserPrincipalName' = $reader['UserPrincipalName']
            'StreetAddress' = $reader['StreetAddress']
            'Country' = $reader['Country']
            'PasswordLastSet' = $reader['PasswordLastSet']
            'MfaDate' = $reader['MfaDate']}
            $OutputObject = New-Object -TypeName PSObject -Property $props
            $OutputObject
        }
    }#end process block
    
    END 
    {
        Write-Verbose 'Closing connection for Find-DomainPls function'
        $Conn.Close()
    }
}

function Get-DomainAdUpdate
{
 <#
.SYNOPSIS
Searches users in Active Directory.

.DESCRIPTION
Searches users in Active Directory.  This function is used to check if a user has set a password.  If 
the user has set a password, the PasswordLastSet value will no longer be NULL.  Only users with a value in PasswordLastSet
will output as an object.

.PARAMETER Identity
SamAccountName

.PARAMETER Server
Domain controller to use for searches

.INPUTS
Takes object as an input.  Object must have Identity and Country as data members.

.OUTPUTS
Custom object with the following fields:  SamAccountName and EmailAddress

.EXAMPLE
Get-DomainAdUpdate -identity 'daniel.rowe', 'adtest5' -server na-us-idc4 -verbose
'daniel.rowe', 'adtest5' | Get-DomainAdUpdate -server na-us-idc4 -verbose

.Parameter LogTable
Used to specify a log table for logging events

.Example
Get-DomainAdUpdate -Identity 'user' -LogTable 'mfalogtable' -ConnectionString 'ConnnectionString'

.Parameter ConnectionString
Used to specify a connection string to the log table

.Parameter LogTable
Used to specify a log table

.Example
Get-DomainAdUpdate -Identity 'user' -LogTable 'mfalogtable' -ConnectionString 'ConnnectionString'

.NOTES
Log object 
$UserNotFoundInAD = @{
            Type = "Failure"
            Source = "Get-DomainAdUpdate"
            Description = "User could not be found in Active Directory"
            UserID = "$($User.UserPrincipalName)"
            Country = "$($User.Country)"
        }
#> 
    [CmdletBinding()]
    param(
    [Parameter(ValueFromPipeline=$true)]
    [object[]]$Identity,

    [Parameter()]
    [string]$Server,

    [Parameter(Mandatory=$false)]
    [string]$LogTable,

    [Parameter(Mandatory=$false)]
    [string]$ConnectionString
    )

    BEGIN
    {
        Write-Verbose 'Getting users from AD'
    }

    PROCESS
    {
        ForEach($User in $Identity)
        {
            try 
            {
                Write-Verbose "Checking $($User.SamAccountName) for a change in PasswordLastSet"
                $Search = Get-Aduser -identity $User.SamAccountName -Properties PasswordLastSet, EmailAddress -Server $Server -ErrorAction Stop
                If($Search.PasswordLastSet)
                {
                    $SearchUsers = New-Object psobject
                    Add-Member -InputObject $SearchUsers -MemberType NoteProperty -Name SamAccountName -Value $Search.SamAccountName
                    Add-Member -InputObject $SearchUsers -MemberType NoteProperty -Name UserPrincipalName -Value $Search.EmailAddress
                    $SearchUsers
                } 
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Verbose "$($User.SamAccountName) could not be found in Active Directory"
                $UserNotFoundInAD = @{
                    Type = "Failure"
                    Source = "Get-DomainAdUpdate"
                    Description = "User could not be found in Active Directory"
                    UserID = "$($User.SamAccountName)"
                    Country = "$($User.Country)"
                }
                New-DomainEventObject @UserNotFoundInAD | Write-DomainMfaLog -LogTable $LogTable -ConnectionString $ConnectionString
            }
        }
    }

    END
    {
        Write-Verbose 'Finished checking users with Get-DomainAdUpdate function'
    }
}

function Get-DomainMfaEligible
{
<#
.SYNOPSIS
 Finds users in AD that are eligible for MFA

.DESCRIPTION
 Finds users in AD that are eligible for MFA.  Users are also filtered by location.  If the location is 
 supported by Paige, these users are excluded from output. Paige locations are considered entire countries.

.PARAMETER IseExclusions
Countries where ISE buildings exist.  Values are two letter country codes e.g.:  US, GB, CA.
Entries are separated by commas.  If no exclusions, all users in AD will be returned.

.PARAMETER Server
Specifies the Active Directory Domain Services instance to connect to, by providing one of the following values 
for a corresponding domain name or directory server. 

.INPUTS
None

.OUTPUTS
Custom object with the following fields:  identity, UserPrincipalName, Street Address, County, PasswordLastSet

.NOTES

.EXAMPLE
Get-DomainMfaEligible -IseExclusions 'US','GB' -Server FQDN
Excludes US and GB and queries a specific server

.EXAMPLE
Get-DomainMfaEligible -IseExclusions (Get-Content -path FILE) -Server FQDN
Gets exclusions from a flat text file
#>

    [CmdletBinding()]
    param
    (
        [Parameter()]
        [string[]]$IseExclusions,
        [Parameter()]
        [string]$Server
    )
    BEGIN
    {   
        Write-Verbose 'Getting All AD users' 
        If ($Server)
        {
            $Users = Get-ADUser -Filter * -Properties EmailAddress, Passwordlastset, StreetAddress, Country, extensionAttribute6, extensionAttribute7, whenCreated -Server $Server
        }
        else 
        {
            $Users = Get-ADUser -Filter * -Properties EmailAddress, Passwordlastset, StreetAddress, Country, extensionAttribute6, extensionAttribute7, whenCreated
        }
    
        #Array to hold eligible user objects
        $MfaEligible = @()
        Write-Verbose 'Filtering out users with missing or bad attributes'
        ForEach ($User in $Users)
        {
            #A valid user is enabled, Email address is equal to EA6 (Domain standard),Country is not empty, and the user
            #has an email address.  Additionally, WhenCreated is less than 30 days from today 
            [bool]$ValidUser = ((((! $User.PasswordLastSet) -and
                                ($User.Enabled -eq $true) -and
                                ($User.WhenCreated -gt (Get-Date).AddDays(-30) -and
                                ($User.extensionAttribute6 -notmatch "Service") -and
                                ($User.EmailAddress -eq $User.extensionAttribute6) -and
                                (! $User.Country) -and
                                ($User.extensionAttribute7 -ne 'duo') -and
                                (! $User.EmailAddress)))))

            If ($ValidUser)
            {
                $MfaEligible += $User
            }
        }
    }

    PROCESS
    {
        #If no IseExclusions find user objects and create a new output object.
        If(! $IseExclusions)
        {
            Write-Verbose 'No ISE Excluded users'
            ForEach($User in $MfaEligible)
            {
                #Create new object and populate datamembers
                $IseExcludedUsers = New-Object psobject
               
                Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name SamAccountName -Value $User.SamAccountName
                Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name UserPrincipalName -Value $User.EmailAddress
                Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name PasswordLastset -Value 'NotSet' 
                
                #Properties cannot be empty
                If (! $User.StreetAddress)
                {
                    Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name StreetAddress -Value 'NotSet'
                }
                else 
                {
                    Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name StreetAddress -Value $User.StreetAddress
                }

                If (! $User.Country)
                {
                    Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name Country -Value 'NotSet'
                }
                else 
                {
                    Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name Country -Value $User.Country
                }
        
                $IseExcludedUsers
            }  
        }
        Else 
        {
            #Exclude users in ISE Buildings and add to new object 
            Write-Verbose 'Fiterting out ISE Locations'
            ForEach($User in $MfaEligible)
            {
                ForEach ($Location in $IseExclusions)
                {
                    $Flag = $false
                    If ($User.Country -eq $Location)
                    {
                        $Flag = $true
                        Break
                    }
                }
                If ($Flag -eq $false)
                {
                    #Create new object and populate datamembers
                    $IseExcludedUsers = New-Object psobject
                    Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name SamAccountName -Value $User.SamAccountName
                    Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name UserPrincipalName -Value $User.EmailAddress  
                    Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name PasswordLastset -Value 'NotSet'
                    
                    #Properties cannot be empty
                    If (! $User.StreetAddress)
                    {
                        Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name StreetAddress -Value 'NotSet'
                    }
                    else 
                    {
                        Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name StreetAddress -Value $User.StreetAddress
                    }
    
                    If (! $User.Country)
                    {
                        Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name Country -Value 'NotSet'
                    }
                    else 
                    {
                        Add-Member -InputObject $IseExcludedUsers -MemberType NoteProperty -Name Country -Value $User.Country
                    }
                    #Pipeline object
                    $IseExcludedUsers
                }
            }
        }
    }

    END
    {
        Write-Verbose 'Finished Get-DomainMfaEligible function'
    }
}

function Get-DomainMfaReady
{
 <#
.SYNOPSIS
Gets users from SQL table that are ready to have MFA set.

.DESCRIPTION
Gets users from SQL table that are ready to have MFA set.  Returns an object with UserPrincipalName.  This will be
used in conjuction with another function to enable MFA for a user.

.PARAMETER ConnectionString
Connection string to connecct to SQL

.OUTPUTS
Custom object with the following fields: SamAccountName, UserPrincipalName,StreetAddress,Country,PasswordLastSet,MfaDate

.NOTES

.EXAMPLE
Get-DomainMfaReady -ConnectionString ConnectionString
#>    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString
    )
    
    BEGIN
    {
        Write-Verbose "Getting users from SQL with MFA Date of TODAY'"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn
        [string] $SQLQuery= $('SELECT * FROM mfainfo WHERE MfaDate = CONVERT(date,GetDate())')
    }#end begin block
    
    PROCESS 
    {
        $Cmd.CommandText = $SQLQuery
        $Reader = $Cmd.ExecuteReader()

        while ($Reader.Read()) 
        {
            $props = @{'SamAccountName' = $reader['SamAccountName']
            'UserPrincipalName' = $reader['UserPrincipalName']
            'StreetAddress' = $reader['StreetAddress']
            'Country' = $reader['Country']
            'PasswordLastSet' = $reader['PasswordLastSet']
            'MfaDate' = $reader['MfaDate']}
            $OutputObject = New-Object -TypeName PSObject -Property $props
            $OutputObject
        }
    }#end process block
    
    END 
    {
        Write-Verbose 'Finished getting users with Get-DomainMfaReady function'
        $Conn.Close()
    }
}

function Update-DomainMfaPlsDb
{
 <#
.SYNOPSIS
Updates PasswordLastSet value in SQL table

.DESCRIPTION
Updates PasswordLastSet value in SQL table.  PasswordLastSet value in SQL table is used to determine when a user
has actually started.

.PARAMETER ConnectionString
Connection string to connecct to SQL

.PARAMETER AdUsers
Collection of AD users that should be updated in the table.

.INPUTS
Object with AD accounts and SamAccountName as a property.
.OUTPUTS
None

.NOTES

.EXAMPLE
$Users | Update-DomainMfaPls -ConnectionString $ConnectionString
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [string]$MfaUserTable,
        
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$true)]
        [object[]]$AdUsers
    )
    
    BEGIN 
    {
        Write-Verbose 'Updating users PasswordLastSetValue'
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn
    }#end begin
    
    PROCESS 
    {
        ForEach($AdUser in $AdUsers)
        {  
            Write-Verbose "Updating $($AdUser.SamAccountName)"
            $UserString = $AdUser.SamAccountName
            [string] $SQLQuery =$("UPDATE $MfaUserTable SET PasswordLastSet='Set' WHERE SamAccountName ='$UserString'")
            $Cmd.CommandText = $SQLQuery
            $Cmd.ExecuteNonQuery() | Out-Null
        }
    }#end process
    
    END 
    {
        Write-Verbose 'Finished Update-DomainMfaPlsDb function'
        $Conn.Close()
    }#end end
}

function Write-DomainMfaDate
{
 <#
.SYNOPSIS
Updates the MFADate field in a SQL table.

.DESCRIPTION
Updates the MFADate value in SQL table.  The MFA date is set via an interger value as a parameter.  

.PARAMETER ConnectionString
Connection string to connecct to SQL

.PARAMETER MfaUserTable
Used to secify the user table for MFA

.EXAMPLE
Write-DomainMfaDate -ConnectionString 'ConnectionString' -MfaUserTable 'mfausertable' - MfaDate 3

.PARAMETER MfaDate
Integer value for when the MFA date will be set for a user.

.EXAMPLE
Write-DomainMfaDate -ConnectionString 'ConnectionString' - MfaDate 3

.OUTPUTS
Object with UserPrincipalName as email address

.NOTES

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [int]$MfaDate,

        [Parameter(Mandatory=$true)]
        [string]$MfaUserTable
    )
    
    BEGIN 
    {
        Write-Verbose 'Updating user table.'
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn
    
        [string] $SQLQuery= $("SELECT * FROM $MfaUserTable WHERE PasswordLastSet = 'SET' AND MfaDate IS NULL")

        $Cmd.CommandText = $SQLQuery
        $Reader = $Cmd.ExecuteReader()

        $SQLTable =@()
        while ($Reader.Read()) 
        {
            $props = @{'SamAccountName' = $reader['SamAccountName']
                    'MfaDate' = $reader['MfaDate']}
            $TempObject= New-Object -TypeName PSObject -Property $props
            $SQLTable +=$TempObject
        }
        $conn.Close()
    }
    
    PROCESS 
    {
        Write-Verbose "Setting a MFA date for users in $MfaDate days."
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn

        ForEach($User in $SQLTable)
        {
            Write-Verbose "Setting MFA date for $($User.SamAccountName) for $((Get-Date).AddDays($MfaDate))"
            $UserString = $User.SamAccountName
            [string] $SQLQuery =$("UPDATE $MfauserTable SET MfaDate='$((Get-Date).AddDays($MfaDate))' WHERE SamAccountName ='$UserString'")
            $Cmd.CommandText = $SQLQuery
            $Cmd.ExecuteNonQuery() | Out-Null
        }#End for each
    }#end process
    
    END 
    {
        $Conn.Close()
        Write-Verbose "Finished updating users and closing connection to db."
    }
}

function Write-DomainMfaDb
{
<#
.SYNOPSIS
 Writes users to a SQL table.

.DESCRIPTION
Writes users to a SQL table.  Input is either from a CSV file, or input object from Get-DomainMfaEligible.
The following fields are updated:  identity, UserPrincipalName, Street Address, County, PasswordLastSet
Duplicate users are not added to the table.
 
.PARAMETER ConnectionString
Connection String for the SQL database

.PARAMETER MfaUserTable
Used to secify the user table for MFA

.PARAMETER Adusers
Object array for input.

.INPUTS
Object array

.OUTPUTS
Custom object with the following fields:  identity, UserPrincipalName, Street Address, County, PasswordLastSet

.NOTES

.EXAMPLE
Write-DomainMfaDb -ConnectionString 'ConnectionString' -MfaUserTable 'mfausertable' -ADUsers (Import-Csv -Path C:\Temp\shortlist.csv) -Verbose

#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [string]$MfaUserTable,
        
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True,
        ValueFromPipeline=$True)]
        [object[]]$ADUsers
    )    
    
    BEGIN
    {
        Write-Verbose "Getting existing users from mfainfo database"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn  

        [string] $SQLQuery= $("SELECT * FROM $MfaUserTable WHERE PasswordLastSet = 'NotSet'")

        $Cmd.CommandText = $SQLQuery
        $Reader = $Cmd.ExecuteReader()

        $SQLTable =@()
        while ($Reader.Read()) 
        {
                    $props = @{'SamAccountName' = $reader['SamAccountName']
                            'UserPrincipalName' = $reader['UserPrincipalName']
                            'StreetAddress' = $reader['StreetAddress']
                            'Country' = $reader['Country']
                            'PasswordLastSet' = $reader['PasswordLastSet']
                            'MfaDate' = $reader['MfaDate']}
                $TempObject= New-Object -TypeName PSObject -Property $props
                $SQLTable +=$TempObject
        }
        $conn.Close()
    }#End Begin

    PROCESS
    {
        #Only add unique entries to the table
        Write-Verbose "Checking for duplicates"
        $TableUpdates = @()
        ForEach ($ADUser in $ADUsers)
        {
            $Flag = $false
            ForEach ($User in $SQLTable)
            {
                If ($User.SamAccountName -eq $ADUser.SamAccountName)
                {
                    $Flag = $true
                    break
                }
             
            }#end inner foreach
            If ($Flag -eq $false)
            {
                #add users to array to update table
                $TableUpdates += $ADUser
            }
        }#end outer foreach

        Write-Verbose "Opening a connection to $MfaUserTable"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn
        $Conn.Open()  
        
        $SQLCmd = "INSERT INTO $MfaUserTable (SamAccountName, UserPrincipalName, StreetAddress, Country, PasswordLastSet, DateAdded)
        VALUES (@SamAccountName, @UserPrincipalName, @StreetAddress, @Country, @PasswordLastSet, @DateAdded)"
        
        ForEach ($User in $TableUpdates)
        {   
            $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@SamAccountName', [Data.SQLDBType]::VarChar, 200))).Value = $User.SamAccountName
            $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@UserprincipalName', [Data.SQLDBType]::VarChar, 200))).Value = $User.UserPrincipalName
            $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@StreetAddress', [Data.SQLDBType]::VarChar, 200))).Value = $User.StreetAddress
            $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@Country', [Data.SQLDBType]::VarChar, 200))).Value = $User.Country
            $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@PasswordLastSet', [Data.SQLDBType]::VarChar, 200))).Value = $User.PasswordLastSet
            $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@DateAdded', [Data.SQLDBType]::Date, 200))).Value = (Get-Date)
            $Cmd.CommandText = $SQLCmd
            $Cmd.Prepare()
            $Cmd.ExecuteNonQuery() | Out-Null
            $Cmd.Parameters.Clear()
        }#End foreach to add users to table
    }#end process block

    END
    {
        $Conn.Close()
        Write-Verbose 'Finished with Write-DomainMfaDb function'
    }
}#End function

function Write-DomainMfaLog
{
<#
.SYNOPSIS
Writes events to a SQL table for logging purposes.

.DESCRIPTION
Writes events to a SQL table for logging purposes.  An event object is passed into this function via the pipeline.
 
.PARAMETER ConnectionString
Connection String for the SQL database.

.PARAMETER LogTable
SQL table used for logging events.

.INPUTS
Object from pipeline.

.OUTPUTS
None

.EXAMPLE
New-DomainEventObject | Write-DomainMfaLog -ConnectionString 'ConnectionString' -LogTable 'Logtable'

#>    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,
        
        [Parameter(Mandatory=$true)]
        [string]$LogTable,

        [Parameter(Mandatory=$true,
        ValueFromPipeline=$true)]
        [object]$EventObject
    )

    BEGIN
    {
        Write-Verbose "Opening a connection to $LogTable"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn
        $Conn.Open()  
    }

    PROCESS
    {
        Write-Verbose "Adding Event to $LogTable"
        
        $SQLCmd = "INSERT INTO $LogTable(Type, Source, Description, DateAdded, UserID, Country)
        VALUES (@Type, @Source, @Description,@DateAdded, @UserID, @Country)"

        $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@Type', [Data.SQLDBType]::VarChar, 200))).Value = $EventObject.Type
        $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@Source', [Data.SQLDBType]::VarChar, 200))).Value = $EventObject.Source
        $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@Description', [Data.SQLDBType]::VarChar, 200))).Value = $EventObject.Description
        $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@DateAdded', [Data.SQLDBType]::Date, 200))).Value = ($EventObject.Date)
        $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@UserID', [Data.SQLDBType]::VarChar, 200))).Value = $EventObject.UserID
        $Cmd.Parameters.Add((New-Object Data.SqlClient.SqlParameter('@Country', [Data.SQLDBType]::VarChar, 200))).Value = $EventObject.Country
        $Cmd.CommandText = $SQLCmd
        $Cmd.Prepare()
        $Cmd.ExecuteNonQuery() | Out-Null
        $Cmd.Parameters.Clear()
    }

    END
    {
        Write-Verbose 'Closing Connection to the log table'
        $Conn.Close()
    }
}

function New-DomainEventObject
{
<#
.SYNOPSIS
Creates an event object used for logging events.

.DESCRIPTION
Creates an event object used for looging events.  Event object is either piped to a file or to a another function to log events
in a SQL table.

Datamembers
Type:           String of the type of message. Warning, Failure, Success are the only acceptable values.
Source:         String of the source of the event.
Description:    String of the event description
Date:           Date stamp of the event in the format of MM-DD-YYYY
UserID:         String of the User ID
Country:        String of the User's Country
 
.PARAMETER Type
String of the type of message. Warning, Failure, Success are the only acceptable values.

.PARAMETER Source
String of the source of the event.

.PARAMETER Description
String of the event description

.INPUTS
Via parameter

.OUTPUTS
Event object

.NOTES

.EXAMPLE
$NoUserInCloud =@{
    Type = "Failure"
    Source = "Get-DomainMfa"
    Description = "$User could not be found in O365 Cloud"
}
New-DomainEventObject @ NoUserinCloud 
#>    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Type,
        [Parameter(Mandatory=$true)]
        [string]$Source,
        [Parameter(Mandatory=$true)]
        [string]$Description,
        [Parameter(Mandatory=$true)]
        [string]$UserID,
        [Parameter(Mandatory=$true)]
        [string]$Country
    )
    $OutputObject = New-Object -TypeName PSObject
    $OutputObject | Add-Member -Membertype NoteProperty -Name 'Type' -Value $Type
    $OutputObject | Add-Member -Membertype NoteProperty -Name 'Source' -Value $Source
    $OutputObject | Add-Member -Membertype NoteProperty -Name 'Description' -Value $Description
    $OutputObject | Add-Member -Membertype NoteProperty -Name 'Date' -Value (Get-Date -Format yyyy-MM-dd)
    $OutputObject | Add-Member -MemberType NoteProperty -Name 'UserID' -Value $UserID
    $OutputObject | Add-Member -MemberType NoteProperty -Name 'Country' -Value $Country
    $OutputObject
}

function Get-DomainMfaEmailNotice
{
<#
.SYNOPSIS
Gets users from table that should be notified of MFA enablement.

.DESCRIPTION
Gets users from table that should be notified of MFA enablement. SQL query returns users with MFA date greater than or equal to 3 days in the future,
MFA date equal to today and have a password set

.PARAMETER ConnectionString
Connection String for the SQL database

.PARAMETER MfaUserTable
Name of the user table

.INPUTS
None

.OUTPUTS
Custom object with UserPrincipalName

.EXAMPLE
Get-DomainMfaEmailNotice -ConnectionString 'ConnectionString' -MfaUserTable 'Table'

.NOTES

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [string]$MfaUserTable
    )   

    BEGIN 
    {
        Write-Verbose 'Getting Users from table that should be notified of impending MFA'
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn  

        # [string] $SQLQuery= $("SELECT * FROM $MfaUserTable WHERE PasswordLastSet = 'Set' And MfaDate <= Convert(Date, DateAdd (day, 3, GetDate())) AND mfadate >= Convert(Date, GetDate())")
        [string] $SQLQuery = $("SELECT * FROM $MfaUserTable WHERE MfaDate = Convert(Date, DateAdd (day, 1, GetDate()))")
    }
    
    PROCESS 
    {
        $Cmd.CommandText = $SQLQuery
        $Reader = $Cmd.ExecuteReader()
        while ($Reader.Read()) 
        {
            
            $props = @{'SamAccountName' = $reader['SamAccountName']
            'UserPrincipalName' = $reader['UserPrincipalName']
            'StreetAddress' = $reader['StreetAddress']
            'Country' = $reader['Country']
            'PasswordLastSet' = $reader['PasswordLastSet']
            'MfaDate' = $reader['MfaDate']}
            $OutObject = New-Object -TypeName PSObject -Property $props
            $OutObject
        }
    }
    
    END 
    {
        Write-Verbose 'Closing Connection for Get-DomainMfaEmailNotice function'
        $Conn.Close()
    }
}

function Remove-DomainMfaTableEntries
{
<#
.SYNOPSIS
Removes table entries from MFA tables older than a threshold.

.DESCRIPTION
Removes table entries from MFA tables older than a threshold.  The threshold is given by parameter.  30 would remove any entries older than 30 days from TODAY.

.PARAMETER ConnectionString
Connection String for the SQL database

.PARAMETER Table
Name of the table

.PARAMETER Days
Number of days from today to remove entries from the table

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Remove-DomainMfaTableEntries -ConnectionString 'ConnectionString' -Table 'Table' -Days 30
This removes any entries from the selected table that are older than 30 days.

.NOTES

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [string]$Table,

        [Parameter(Mandatory=$true)]
        [string]$LogTable,

        [Parameter(Mandatory=$true)]
        [int]$Days
    )   

    BEGIN 
    {
        Write-Verbose "Connecting to $Table"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn  

        [string] $SQLQuery= $("DELETE FROM $Table WHERE DateAdded < Convert (Date, Dateadd (day, -$Days, GetDate()))")
    }
    
    PROCESS 
    {
        $Cmd.CommandText = $SQLQuery
        $Cmd.ExecuteNonQuery() | Out-Null

        $RemoveTableEntries = @{
            Type = "Maintenance"
            Source = "Remove-DomainMfaTableEntries"
            Description = "Routine Table maintainence of $Table"
            UserID = "None"
            Country = "None"
        }
        New-DomainEventObject @RemoveTableEntries | Write-DomainMfaLog -LogTable $LogTable -ConnectionString $ConnectionString
    }
    
    END 
    {
        Write-Verbose 'Closing Connection for Remove-DomainMfaTableEntries function'
        $Conn.Close()
    }
}

function Remove-DomainUserFailures
{
<#
.SYNOPSIS
Performs table maintenance for repeated errors from users with a bad SamAccountName in the main user table.

.DESCRIPTION
Performs table maintenance for repeated errors from users with a bad SamAccountName in the main user table.  
If a user has a bad SamAccountName in the main table,repeated checks are made against the user.  
This will result in the error log filling up with reports.  Additionally, the user will never be properly 
checked for MFA enablement.

.PARAMETER ConnectionString
Connection String for the SQL database

.PARAMETER MfaUserTable
Name of the user table

.PARAMETER LogTable
Name of the log table

.PARAMETER EventSource
Event source in the log table

.PARAMETER ErrorThreshold
Number of times the user occurs in the table.

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Remove-DomainUserFailures -MfaUserTable TableName -LogTable Tablename -ConnectionString ConnectionString -ErrorThreshold 4 -EventSource Source

.NOTES

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [string]$MfaUserTable,

        [Parameter(Mandatory=$true)]
        [string]$LogTable,

        [Parameter(Mandatory=$true)]
        [string]$EventSource,

        [Parameter(Mandatory=$true)]
        [int]$ErrorThreshold
    )   

    BEGIN 
    {
        Write-Verbose "Connecting to $LogTable"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn
        
        #SQL parameters for DELETE Query.
        $ConnDelete = New-Object System.Data.SqlClient.SqlConnection
        $ConnDelete.ConnectionString = $ConnectionString
        $ConnDelete.Open()
        $CmdDelete = New-Object System.Data.SqlClient.SqlCommand
        $CmdDelete.Connection = $ConnDelete

        [string] $SQLQuery = $("select type, source, USERID from $Logtable where type='Failure' and source ='get-Domainadupdate' group by type, source, userid having count(*) >= $ErrorThreshold")
        [string] $SQLQueryDelete = $("DELETE FROM $MfaUserTable WHERE samaccountname IN (SELECT USERID FROM $LogTable WHERE type='Failure' AND SOURCE ='get-Domainadupdate' GROUP BY userid HAVING COUNT(*) >= $ErrorThreshold)")
    }
    
    PROCESS 
    {
        $Cmd.CommandText = $SQLQuery
        $Reader = $Cmd.ExecuteReader()

        #Array to hold error users
        $ErrorUsers = @()
        while ($Reader.Read()) 
        {
            $props = @{'UserID' = $reader['UserID']}
            $OutputObject = New-Object -TypeName PSObject -Property $props
            $ErrorUsers += $OutputObject
        }
        
        #Adding the users to the Table
        ForEach($User in $ErrorUsers)
        {
            $DomainUpdateFailures = @{
            Type = "Maintenance"
            Source = "Remove-DomainUserFailures"
            Description = "Removed a bad or nonexistent user from $MfaUserTable"
            UserID = "$($User.UserID)"
            Country = "US"
            }

            New-DomainEventObject @DomainUpdateFailures | Write-DomainMfaLog -LogTable $LogTable -ConnectionString $ConnectionString
        }

        Write-Verbose "Removing users from $MfaUserTable"
        $CmdDelete.CommandText = $SQLQueryDelete
        $CmdDelete.ExecuteNonQuery() | Out-Null
    } # End Process block

    END 
    {
        Write-Verbose 'Closing Connection for Remove-DomainMfaTableEntries function'
        $Conn.Close()
        $ConnDelete.Close()
    }
}

function Remove-DomainLogTableDuplicates
{
<#
.SYNOPSIS
Removes log table duplicates

.DESCRIPTION
Removes log table duplicates.  Duplicate entries are created for failed events.  This is a cleanup function used in 
conjunction with Remove-DomainUserFailures. One entry in the table will be left after the function finishes. 

.PARAMETER ConnectionString
Connection String for the SQL database

.PARAMETER Table
Name of the table

.PARAMETER LogTable
Table to log actions from this function

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Remove-DomainMfaTableEntries -ConnectionString 'ConnectionString' -Table 'Table' -Days 30
This removes any entries from the selected table that are older than 30 days.

.NOTES

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString,

        [Parameter(Mandatory=$true)]
        [string]$Table,

        [Parameter(Mandatory=$true)]
        [string]$LogTable
    )   

    BEGIN 
    {
        Write-Verbose "Connecting to $Table"
        $Conn = New-Object System.Data.SqlClient.SqlConnection
        $Conn.ConnectionString = $ConnectionString
        $Conn.Open()
        $Cmd = New-Object System.Data.SqlClient.SqlCommand
        $Cmd.Connection = $Conn  

        [string] $SQLQuery= $("WITH mfainfoCTE AS (Select *, ROW_NUMBER() OVER (PARTITION BY UserID ORDER BY UserID) AS RowNumber From $Table) Delete from mfainfoCTE Where UserID <> 'None' And RowNumber >= 2 and Type = 'Failure'")
    }
    
    PROCESS 
    {
        Write-Verbose 'Removing Duplicates'
        $Cmd.CommandText = $SQLQuery
        $Cmd.ExecuteNonQuery() | Out-Null

        $DomainRemoveLogDups = @{
            Type = "Maintenance"
            Source = "Remove-DomainLogTableDuplicates"
            Description = "Routine Table maintainence of $Table"
            UserID = "None"
            Country = "None"
        }
        New-DomainEventObject @DomainRemoveLogDups | Write-DomainMfaLog -LogTable $LogTable -ConnectionString $ConnectionString
    }
    
    END 
    {
        Write-Verbose 'Closing Connection for Remove-DomainLogTableDuplicates function'
        $Conn.Close()
    }
}