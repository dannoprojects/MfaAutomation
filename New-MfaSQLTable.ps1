$conn_string = "Server=localhost\SQLEXPRESS;Database=master;Trusted_Connection=True;"
$conn = New-Object System.Data.SqlClient.SqlConnection
$conn.ConnectionString = $conn_string
$conn.Open()

$sql = @"

CREATE DATABASE MFA; 

"@

$cmd = New-Object System.Data.SqlClient.SqlCommand
$cmd.CommandText = $sql
$cmd.Connection = $conn
$cmd.ExecuteNonQuery()
$conn.close()

function New-MFASQLTable 
{
    [CmdletBinding()]
    param()
    $DiskInfoSqlConnection = "Server=localhost\SQLEXPRESS;Database=MFA;Trusted_Connection=True;"
    $conn = New-Object System.Data.SqlClient.SqlConnection
    $conn.ConnectionString = $DiskInfoSqlConnection
    $conn.Open()
    $sql = @"
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='mfainfo' AND xtype='U')
            CREATE TABLE mfainfo (
                SamAccountName VARCHAR(64),
                UserPrincipalName VARCHAR(64),
                StreetAddress VARCHAR(64),
                Country VARCHAR(64),
                PasswordLastSet VARCHAR(64),
		        DateAdded DATETIME2,
                MfaDate DATETIME2
            )
"@

    $cmd = New-Object System.Data.SqlClient.SqlCommand
    $cmd.Connection = $conn
    $cmd.CommandText = $sql
    $cmd.ExecuteNonQuery() #| Out-Null
    $conn.Close()
}

New-MFASQLTable