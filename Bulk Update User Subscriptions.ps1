# Run PowerShell as Administrator
# Download the latest Azure PowerShell SDK here - http://aka.ms/webpi-azps

[CmdletBinding()]
param
(
)

function IsWindows
{
    # Cross-Platform PowerShell has variables $IsWindows $IsLinux and $IsOSX.
    if ($Null -eq $IsWindows)
    {
        return $true
    } else {
        if ($IsWindows)
        {
            return $true
        }
        else {
             return $false
        }
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

    # If running in PowerShell ISE, then display custom messages in Green
    if ($Host.Name -eq "Windows PowerShell ISE Host") {
        $Host.PrivateData.VerboseBackgroundColor = 'Green'
    }

    Write-Verbose -Message $Message

    if ($Host.Name -eq "Windows PowerShell ISE Host") {
        $Host.PrivateData.VerboseBackgroundColor = $Host.PrivateData.DefaultOptions.VerboseBackgroundColor
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
		$ModuleLatest = Find-Module -Name $ModuleName -Repository $RepositoryName -ErrorAction Stop
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

            # Create Install-Module cmdlet arguments
            $splat= @{
                Name = $ModuleName 
                RequiredVersion = $ModuleLatest.Version 
                Repository = $Repository.Name 
                Scope = AllUsers 
                SkipPublisherCheck = $true 
                AllowClobber = $true
                Force = $true
                ErrorAction = 'Stop'
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

            # Create Install-Module cmdlet arguments
            $splat = @{
                Name = $ModuleName 
                RequiredVersion = $ModuleLatest.Version 
                Repository = $Repository.Name 
                Scope = AllUsers 
                SkipPublisherCheck = $true 
                AllowClobber = $true
                Force = $true
                ErrorAction = 'Stop'
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
Install-PowerShellModule -RepositoryName 'PSGallery' -ModuleName 'AzureRM.Resources'
 
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
    $AzureADAdmin =  Connect-AzureAD -ErrorAction Stop
}
catch
{
    Write-Warning -Message "Unable to connect to Azure AD"
    exit
}

$AzureADAdminDomainName = ($AzureADAdmin.Account.Id -split "@")[1]

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

    Clear-Variable -Name GivenName, Surname, UpdatedGivenName, UpdatedSurname, UserPrincipalName, UpdatedUserPrincipalName, Year, Password -ErrorAction SilentlyContinue -Force

    [String]$GivenName = $($ArrayUser[0])
    [String]$Surname = $($ArrayUser[1])
    [String]$UserPrincipalName = $GivenName.ToLower() + $Surname.ToLower() + "@" + $AzureADAdminDomainName.ToLower()
    [String]$Year = $(Get-Date).Year.ToString()
    [String]$Password = "pass@word" + $Year
    [SecureString]$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

    if ($ArrayUser[2] -and $ArrayUser[3])
    {
        [String]$UpdatedGivenName = $($ArrayUser[2])
        [String]$UpdatedSurname = $($ArrayUser[3])
        [String]$UpdatedUserPrincipalName = $UpdatedGivenName.ToLower() + $UpdatedSurname.ToLower() + "@" + $AzureADAdminDomainName.ToLower()
    }

    try
    {
        $AzureADUserCredential = New-Object System.Management.Automation.PsCredential($UserPrincipalName,$SecurePassword) -ErrorAction Stop
        $AzureRMUser = Add-AzureRmAccount -Credential $AzureADUserCredential -ErrorAction Stop
        Write-Status -Message "Logged on as User $UserPrincipalName"
    }
    catch
    {
        try
        {
            $AzureADUserCredential = New-Object System.Management.Automation.PsCredential($UpdatedUserPrincipalName,$SecurePassword) -ErrorAction Stop
            $AzureRMUser = Add-AzureRmAccount -Credential $AzureADUserCredential -ErrorAction Stop
            Write-Status -Message "Logged on as User $UpdatedUserPrincipalName"
        }
        catch
        {
            Write-Status -Message "Unable to log in as either User $UserPrincipalName or $($UpdatedUserPrincipalName)"
            exit
        }
    }

    try
    {
        if (!($AzureRMUser.Context.Subscription))
        {
            Write-Status -Message "$($AzureRMUser.Context.Account.Id) does not have an Azure subscription"
        }
        else
        {
            New-AzureRMRoleAssignment -SignInName $($AzureADAdmin.Account) -RoleDefinitionName "Owner" -ErrorAction Stop
            Write-Status -Message "$($AzureADAdmin.Account.Id) added to Owner role"
        }
    }
    catch
    {
        if ($_.Exception.Error.Code -eq 'RoleAssignmentExists')
        {
            Write-Status -Message "$($AzureADAdmin.Account.Id) is already added to Owner role"
        }
        else
        {
            Write-Status -Message "Unable to add $($AzureADAdmin.Account.Id) to Owner role"
            exit
        }
    }

}
