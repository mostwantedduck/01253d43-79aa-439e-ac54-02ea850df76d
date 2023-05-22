$Global:Spacing   = "`t"
$Global:PlusLine  = "`t[+]"
$Global:InfoLine  = "`t[*]"
$Global:InfoLine1 = "[*]"

#
# Constants for Groups
#

$Global:GroupSenior = "Senior Management"
$Global:GroupITAdmins = "IT Admin"
$Global:GroupEngineering = "Engineering"
$Global:GroupSales = "Sales"


$Global:Groups = @(
    [PSCustomObject]@{
        Name = $Global:GroupSenior;
        OU = $Global:GroupSenior.replace(' ' , '-');
    },
    [PSCustomObject]@{
        Name = $Global:GroupITAdmins;
        OU = $Global:GroupITAdmins.replace(' ' , '-');
    },
    [PSCustomObject]@{
        Name = $Global:GroupEngineering;
        OU = $Global:GroupEngineering.replace(' ' , '-');
    },
    [PSCustomObject]@{
        Name = $Global:GroupSales;
        OU = $Global:GroupSales.replace(' ' , '-');
    }
)

# Domain Information
$Global:Domain = "";

$Global:Users = @(
    #
    # Senior Management Group (1)
    #
    [PSCustomObject]@{
            firstname = "Count";
            lastname = "Dooku";
            password = "C0nc0Rd1776!";
            group = $Global:GroupSenior;
            additionalGroups = @(
                "Domain Admins"
            );
        },

    #
    # IT Admins (1)
    #
    [PSCustomObject]@{
            firstname = "Han";
            lastname = "Solo";
            password = "Lexington1776!";
            group = $Global:GroupITAdmins;
            additionalGroups = @(
                "Administrators"
            );
        },

    #
    # Engineering (5)
    #
    [PSCustomObject]@{
            firstname = "Emperor";
            lastname = "Palpatine";
            password = "H1dD3nV4ll3y!";
            group = $Global:GroupEngineering;
            additionalGroups = $null;
        },
    [PSCustomObject]@{
            firstname = "Darth";
            lastname = "Vader";
            password = "AhArGuY5Nm7U3!@";
            group = $Global:GroupEngineering;
            additionalGroups = $null;
        },
    [PSCustomObject]@{
            firstname = "Kylo";
            lastname = "Ren";
            password = "L4k3LiV3L0ve!";
            group = $Global:GroupEngineering;
            additionalGroups = $null;
        },
    [PSCustomObject]@{
            firstname = "Leia";
            lastname = "Organa";
            password = "Baseball123!";
            group = $Global:GroupEngineering;
            additionalGroups = $null;
        },
    [PSCustomObject]@{
            firstname = "Obi-Wan";
            lastname = "Kenobi";
            password = "Phi11i35@44";
            group = $Global:GroupEngineering;
            additionalGroups = $null;
        },

    #
    # Sales (3)
    #
    [PSCustomObject]@{
            firstname = "Anakin";
            lastname = "Skywalker";
            password = "FallOutBoy1!";
            group = $Global:GroupSales;
            additionalGroups = $null;
        },
    [PSCustomObject]@{
            firstname = "Luke";
            lastname = "Skywalker";
            password = "Password123!";
            group = $Global:GroupSales;
            additionalGroups = $null;
        },
    [PSCustomObject]@{
            firstname = "Padme";
            lastname = "Amidala";
            password = "M0t0rH3Ad65^$#";
            group = $Global:GroupSales;
            additionalGroups = $null;
        }
)

function Write-Good { 
    param( $String ) 
    Write-Host $Global:InfoLine $String $Global:InfoLine1 -ForegroundColor 'Green' 
}

function Write-Info { 
    param( $String ) 
    Write-Host $Global:PlusLine  $String -ForegroundColor 'Gray'
}

function Write-Fault { 
    param( $String ) 
    Write-Host $Global:PlusLine  $String -ForegroundColor 'Red'
}

function Set-RenameDC {
    param (
        [Parameter(Mandatory=$true)]
        [System.String]$DomainName
    )

    $username = whoami
    $domainFront = $DomainName.split('.')[0].toUpper()
    $newDCName = "$domainFront-DC"

    Write-Good "-- Renaming the domain controller to $newDCName"

    Rename-Computer -NewName $newDCName -DomainCredential $username -PassThru
}

function Set-MakeShareFolder {
    try {
        New-Item -ItemType Directory -Path "C:\Users\Public\Shared"
        New-SmbShare -Name "Shared" -Path "C:\Users\Public\Shared" -ReadAccess "Users"
    }
    catch {
        Write-Fault "!!! Error: $($_.Exception.Message)"
    } 
}

function Add-ADGroupsAndOrganizationalUnits {
    $domainFront = $Global:Domain.split('.')[0]
    $domainBack = $Global:Domain.split('.')[1]

    Write-Good "-- Creating Domain Groups"

    foreach ($group in $Global:Groups) {
        try {
            New-ADGroup -name $group.Name -GroupScope Global
            Write-Info "--- Adding $group.Name to $Global:Domain"
        }
        catch {
            Write-Fault "!!! Error: Adding $group.Name to $Global:domain --> $($_.Exception.Message)"
        }
    }

    Write-Good "-- Generating Organizational Units for the $Global:domain."
    
    foreach ($group in $Global:Groups) {
        try {
            $path = "DC={0},DC={1}" -f ($domainFront, $domainBack)
            New-ADOrganizationalUnit -Name $group.OU -Path $path
            Write-Info "--- Adding $group.OU to $Global:domain Organizational Unit"
        }
        catch {
            Write-Fault "!!! Error: Adding $group.OU to $Global:Domain Organizational Unit --> $($_.Exception.Message)"
        }
    }
    
    Write-Info "-- Organizational Units were added."
}

function Add-UsersToGroup {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Users
    )

    $domainFront = $Global:domain.split('.')[0]
    $domainBack = $Global:domain.split('.')[1]

    foreach ($user in $Users) {
        $firstname = $user.firstname
        $lastname = $user.lastname
        $fullname = "{0} {1}" -f ($firstname, $lastname)
        $password = $user.password

        # TODO: Handle better the samaccountname and principalname generation and dups
        $SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
        $principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
    

        $ou = $Global:Groups | Where-Object { $_.Name -eq $user.group }
        $path = "OU={0},DC={1},DC={2}" -f ($ou.OU, $domainFront, $domainBack)
        
        $userPrincipalName = "{0}@{1}" -f ($principalname, $Global:Domain)

        try {
            New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $userPrincipalName -Path $path -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
            
            Write-Info "-- $SamAccountName added"

            if ($user.additionalGroups -ne $null) {
                foreach ($additionalGroup in $user.additionalGroups) {
                    Write-Info "--- Adding $SamAccountName to $additionalGroup"
                    Add-ADGroupMember -Identity $additionalGroup -Members $SamAccountName
                }
            }
        }
        catch {
            Write-Fault "!!! Error: Adding $SamAccountName --> $($_.Exception.Message)"
        }
    }
}

function Add-CustomUsers {
    $domainFront = $Global:Domain.split('.')[0]
    $domainBack = $Global:Domain.split('.')[1]

    # Create IIS service account
    New-ADUser -Name "IIS Service Account" `
        -SamAccountName iis_svc -UserPrincipalName iis_svc@$Global:Domain `
        -AccountPassword (convertto-securestring "Passw0rd" -asplaintext -force) `
        -PasswordNeverExpires $True `
        -PassThru | Enable-ADAccount

    New-ADUser -Name "SQL Service Account" `
        -SamAccountName sql_svc -UserPrincipalName sql_svc@$Global:Domain `
        -AccountPassword (convertto-securestring "Passw0rd" -asplaintext -force) `
        -PasswordNeverExpires $True `
        -PassThru | Enable-ADAccount
}

function Add-ASREPRoasting {
    param (
        [Parameter(Mandatory=$true)]
        [System.String]$UserName
    )
    Write-Good "-- Modifying pre-authentication privileges"
    Set-ADAccountControl -Identity $UserName -DoesNotRequirePreAuth 1
    Write-Info "-- ASREP privileges granted to $UserName"
}

function Add-Kerberoasting {
    param (
        [Parameter(Mandatory=$true)]
        [System.String]$username,

        [Parameter(Mandatory=$true)]
        [System.String]$domainName,
	
        [Parameter(Mandatory=$true)]
        [System.Int16] $spnPort
    )
    
    try {
        Write-Info $domainName
        Write-Info $username
        $hostname = $domainName.split('.')[0].toUpper()
        Write-Info $hostname
        Write-Good "-- Adding Kerberoastable service account to domain"
	    # setspn -A <user_name>/<hostname>.<domain>:<port> <user_name>
        $spnIdentification = "{0}/{1}.{2}:{3}" -f $username, $hostname, $domainName, $spnPort
        Write-Info $spnIdentification
	    setspn -A $spnIdentification $username
        Write-Info "-- $UserName service account added"
    }
    catch {
        Write-Fault "!!! Error: Add-Kerberoasting --> $($_.Exception.Message)"
    }
}

function Set-AddCustomACL {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Destination,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Security.Principal.IdentityReference]$Source,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Rights

        )
        $ADObject = [ADSI]("LDAP://" + $Destination)
        $identity = $Source
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
        $type = [System.Security.AccessControl.AccessControlType] "Allow"
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
        $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
        $ADObject.psbase.commitchanges()
}

function Set-BadACLs {
    Write-Good "-- [1] Granting $GroupITAdmins GenericAll rights on Domain Admins."
    $DestinationGroup = Get-ADGroup -Identity $GroupITAdmins
    $SourceGroup = Get-ADGroup -Identity "Domain Admins"
    Set-AddCustomACL -Source $DestinationGroup.sid -Destination $SourceGroup.DistinguishedName -Rights "GenericAll"
    Write-Info "---> $GroupITAdmins group granted GenericAll permissions for the Domain Admins group."
    
    Write-Good "-- [2] Adding misconfigured ACL rule for the $GroupEngineering group."
    $DestinationGroup = Get-ADGroup -Identity $GroupEngineering
    $SourceGroup = Get-ADGroup -Identity $GroupITAdmins
    Set-AddCustomACL -Source $DestinationGroup.sid -Destination $SourceGroup.DistinguishedName -Rights "GenericAll"
    Write-Info "---> Whoops! GenericAll rights granted to $GroupEngineering."
    
    Write-Good "-- [3] Adding misconfigured ACL rule for Obi-Wan Kenobi."
    $vulnAclUser = Get-ADUser -Identity "o.kenobi"
    $SourceUser = Get-ADUser -Identity "h.solo"
    Set-AddCustomACL -Source $vulnAclUser.sid -Destination $SourceUser.DistinguishedName -Rights "GenericAll"
    Write-Info "---> Whoops! GenericAll rights granted to o.kenobi."

    Write-Good "-- [4] Adding misconfigured ACL rule for the $GroupSales group."	
    $DestinationGroup = Get-ADGroup -Identity $GroupSales
    $SourceGroup = Get-ADGroup -Identity $GroupEngineering
    Set-AddCustomACL -Source $DestinationGroup.sid -Destination $SourceGroup.DistinguishedName -Rights "GenericAll"
    Write-Info "---> Whoops! GenericAll rights granted to $GroupSales."
}	

function Invoke-ADGenerator {
	Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName
    )

    $Global:Domain = $DomainName

    Set-RenameDC -DomainName $DomainName
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "Domain controller renamed."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Set-MakeShareFolder
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "Shared folder created."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Add-ADGroupsAndOrganizationalUnits
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "Group creation completed."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Add-UsersToGroup -Users $Global:Users
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "User creation completed"
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Add-ASREPRoasting -UserName "l.skywalker"
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "ASREP settings update completed."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Add-CustomUsers
    Add-Kerberoasting -username "iis_svc" -domainName $DomainName -spnPort 8080
    Add-Kerberoasting -username "sql_svc" -domainName $DomainName -spnPort 1433
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "Kerberoastable service creation completed."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Set-BadACLs
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "ACL misconfigurations completed."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Write-Good "                                                                                "
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "Domain-wide PowerShell Remoting GPO configuration completed."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 1

    Write-Good "                                                                                "
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "IMPORTANT:"
    Write-Good "Some changes require a restart to take effect. Restarting your domain controller"
    Write-Good "in 30 seconds."
    Write-Good "--------------------------------------------------------------------------------"
    Write-Good "                                                                                "
    Start-Sleep -Seconds 30

    Restart-Computer
}
