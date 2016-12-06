# Run PowerShell as Administrator
# Download the latest Azure PowerShell SDK here - http://aka.ms/webpi-azps

[CmdletBinding()]
param
(
)

function IsWindows
{
    $IsVars = Get-Variables is*
    if ([String]::IsNullOrEmpty($IsVars))
    {
        $return = $true
    } else {
        $return = $false
    }
    return $return
}

function Write-Status
{
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Message
	)

    if ($psise) {
        $host.PrivateData.VerboseBackgroundColor = 'Green'
    }

    Write-Verbose -Message $Message

    if ($psise) {
        $host.PrivateData.VerboseBackgroundColor = $host.PrivateData.DefaultOptions.VerboseBackgroundColor
    }
}

function Install-PowerShellModule
{
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.String]$RepositoryName,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ModuleName
	)

	Try
	{
		$ModuleLatest = Find-Module -Name $ModuleName -Repository $Repository.Name -ErrorAction Stop
        Write-Status -Message "Find PowerShell module $ModuleName in repository $RepositoryName"
	}
	catch
	{
		Write-Warning -Message "Unable to find PowerShell module '$ModuleName' in repository '$Repository.Name'"
        exit
	}

	Try
	{
		$ModuleInstalled = Get-InstalledModule -Name $ModuleName -ErrorAction Stop
        Write-Status -Message "PowerShell module $ModuleName is installed on this computer"
	}
	catch
	{
		Write-Status -Message "PowerShell module '$ModuleName' is not installed on this computer"
	}

	if ($ModuleInstalled -eq $null)
	{
        try
        {

            # Create splat for the cmdlet arguments
            $splat = @{
                Name = $ModuleName 
                RequiredVersion = $ModuleLatest.Version 
                Repository = $Repository.Name 
                Scope = AllUsers 
                SkipPublisherCheck = $true 
                AllowClobber = $true
                Force = $true
                ErrorAction = Stop
            }

		    $Module = Install-Module @splat
					      
		    Write-Status -Message "Installed PowerShell module $ModuleName v$($ModuleLatest.Version) from repository $($Repository.Name)"
        }
        catch
        {
		    Write-Warning -Message "Failed to install PowerShell module $ModuleName v$($ModuleLatest.Version) from repository $($Repository.Name)"
            exit
        }
	}
	elseif ($ModuleLatest.Version -gt $ModuleInstalled.Version)
	{
        try
        {

            # Create splat for the cmdlet arguments
            $splat = @{
                Name = $ModuleName 
                RequiredVersion = $ModuleLatest.Version 
                Repository = $Repository.Name 
                Scope = AllUsers 
                SkipPublisherCheck = $true 
                AllowClobber = $true
                Force = $true
                ErrorAction = Stop
            }

		    $Module = Install-Module @splat
		    Write-Status -Message "Updated PowerShell module $ModuleName from v$($ModuleInstalled.Version) to v$($ModuleLatest.Version) from repository $($Repository.Name)"
        }
        catch
        {
		    Write-Warning -Message "Unable to update PowerShell module $ModuleName from v$($ModuleInstalled.Version) to v$($ModuleLatest.Version) from repository $($Repository.Name)"
            $_.exception
            exit
        }
	}
}

function Set-CustomExecutionPolicy
{
    param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
        [ValidateSet("CurrentUser","LocalMachine")]
		[System.String]$Scope,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
        [ValidateSet("Unrestricted", "RemoteSigned")]
		[System.String]$ExecutionPolicy
	)

    $Policy = Get-ExecutionPolicy -Scope $Scope
    If ($Policy -ne "RemoteSigned" -and $Policy -ne "Unrestricted")
    {
        Try
        {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope $Scope -ErrorAction Stop -Force
            Write-Status -Message "Set PowerShell execution policy $ExecutionPolicy for scope $Scope"
        }
        Catch
        {
            Write-Warning -Message "Failed to set PowerShell execution policy $ExecutionPolicy for scope $Scope"
		    exit
        }
    }
}

$VerbosePreference = "Continue"

Write-Status -Message "Starting script $($MyInvocation.MyCommand)"

# Check PowerShell is running as administrator (Windows) or root (Linux & MacOS)
if (IsWindows)
{
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”))
    {
        Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
        exit
    }
}
else {
    if ((Invoke-Expression 'whoami') -ne "root")
    {
        Write-Warning “You do not have root access to run this script!`nPlease restart PowerShell with sudo!”
        exit
    }
}

# Set PowerShell execution policies
Set-CustomExecutionPolicy -Scope 'LocalMachine' -ExecutionPolicy Unrestricted

# Install pre-requisite PowerShell modules
Install-PowerShellModule -RepositoryName 'PSGallery' -ModuleName 'AzureAD'
 
# File Open dialog to select the Azure AD Users file
$dialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
$dialog.AddExtension = $true
$dialog.Filter = 'Text Files (*.txt)|*.txt|All Files|*.*'
$dialog.Multiselect = $false
$dialog.FilterIndex = 0
$dialog.RestoreDirectory = $true
$dialog.Title = 'Select a file containing Azure Users'
$result = $dialog.ShowDialog()
if ($result = 'OK')
{
    $filename = $dialog.FileName
    if (!($filename))
    {
        Write-Warning “No file selected”
        exit
    }
} 

$ArrayUsers = Get-Content -Path $filename

try
{
    $AzureADUser = Connect-AzureAD
}
catch
{
    Write-Warning -Message "Unable to connect to Azure AD"
    exit
}

$AzureADUserID = $AzureADUser.Account.Id
$AzureADUserDomainName = ($AzureADUserID -split "@")[1]

foreach ($ArrayUser in $ArrayUsers)
{
    $ArrayUser = $ArrayUser -split ','

    if (!($ArrayUser))
    {
        Write-Warning -Message 'User array cannot be NULL'
        exit

    }

    if (!($ArrayUser[0]) -or !($ArrayUser[1]))
    {
        Write-Warning -Message 'User[0] or User[1] cannot be NULL'
        exit
    }

    Clear-Variable -Name NewUser, UpdatedUser -ErrorAction SilentlyContinue -Force
    Clear-Variable -Name GivenName, Surname, UserPrincipalName, DisplayName, MailNickName -ErrorAction SilentlyContinue -Force
    Clear-Variable -Name UpdatedGivenName, UpdatedSurname, UpdatedUserPrincipalName, UpdatedDisplayName, UpdatedMailNickName -ErrorAction SilentlyContinue -Force
    Clear-Variable -Name TelephoneNumber, UsageLocation, Country, UserType, Year, Password, PasswordProfile -ErrorAction SilentlyContinue -Force

    [String]$GivenName = $($ArrayUser[0])
    [String]$Surname = $($ArrayUser[1])
    [String]$UserPrincipalName = $GivenName.ToLower() + $Surname.ToLower() + "@" + $AzureADUserDomainName.ToLower()
    [String]$DisplayName = $GivenName + " " + $Surname
    [String]$MailNickName = $GivenName.ToLower() + $Surname.ToLower()
    [String]$TelephoneNumber = "+44 3448002400"
    [String]$UsageLocation = "GB"
    [String]$Country = "GB"
    [String]$UserType = "Member"
    [String]$Year = $(Get-Date).Year.ToString()
    [String]$Password = "pass@word" + $Year
    [Boolean]$ForceChangePasswordNextLogin = $false
    [Microsoft.Open.AzureAD.Model.PasswordProfile]$PasswordProfile=@{"password"=$Password;"forceChangePasswordNextLogin"=$ForceChangePasswordNextLogin}

    if ($ArrayUser[2] -and $ArrayUser[3])
    {
        [String]$UpdatedGivenName = $($ArrayUser[2])
        [String]$UpdatedSurname = $($ArrayUser[3])
        [String]$UpdatedUserPrincipalName = $UpdatedGivenName.ToLower() + $UpdatedSurname.ToLower() + "@" + $AzureADUserDomainName.ToLower()
        [String]$UpdatedDisplayName = $UpdatedGivenName + " " + $UpdatedSurname
        [String]$UpdatedMailNickName = $UpdatedGivenName.ToLower() + $UpdatedSurname.ToLower()
    }

    try
    {
        $NewUser = Get-AzureADUser -ObjectId $UserPrincipalName -ErrorAction Stop
        Write-Status -Message "User $UserPrincipalName already exists."
    }
    catch
    {
        try
        {
            $UpdatedUser = Get-AzureADUser -Filter "OtherMails eq '$UserPrincipalName'" -Top 1 -ErrorAction Stop
            if ($UpdatedUser)
            {
                Write-Status -Message "User $UserPrincipalName has already been updated to $($UpdatedUser.UserPrincipalName)"
            }
        }
        catch
        {
        }
    }

    If (!($NewUser) -and !($UpdatedUser))
    {
        try
        {
            $splat = @{
                DisplayName = $DisplayName 
                GivenName = $GivenName 
                Surname = $Surname 
                UserPrincipalName = $UserPrincipalName 
                MailNickName = $MailNickName 
                TelephoneNumber = $TelephoneNumber 
                Country = $Country 
                UsageLocation = $UsageLocation 
                AccountEnabled = $true 
                UserType = $UserType 
                PasswordProfile = $PasswordProfile 
                ErrorAction = Stop
            }

            $NewUser = NewAzureADUser @splat
            Write-Status -Message "Created user $UserPrincipalName."
        }
        catch
        {
            Write-Warning -Message "Unable to create user $UserPrincipalName."
            exit
        }
    }

    if ($NewUser -and !($UpdatedUser) -and $UpdatedUserPrincipalName)
    {
        try
        {

            $splat = @{
                ObjectId = $NewUser.ObjectId
                DisplayName = $UpdatedDisplayName
                GivenName = $UpdatedGivenName
                Surname = $UpdatedSurname
                UserPrincipalName = $UpdatedUserPrincipalName
                MailNickName = $UpdatedMailNickName
                TelephoneNumber = $TelephoneNumber
                Country = $Country
                UsageLocation = $UsageLocation
                AccountEnabled = $true
                UserType = $UserType
                PasswordProfile = $PasswordProfile
                OtherMails = $UserPrincipalName
                ErrorAction = Stop
            }

             Set-AzureADUser @splat
            Write-Status -Message "Updated user $($NewUser.UserPrincipalName) to $($UpdatedUserPrincipalName)"
        }
        catch
        {
            Write-Warning -Message "Unable to update user $($NewUser.UserPrincipalName)."
            exit
        }
    }
}