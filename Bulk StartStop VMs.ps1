# Run PowerShell as Administrator
# Download the latest Azure PowerShell SDK here - http://aka.ms/webpi-azps

[CmdletBinding()]
Param
(
	[Parameter(Mandatory=$true, HelpMessage="Valid values are 'Status', 'Start' or 'Stop'")]
    [ValidateSet("Status","Start","Stop", ignorecase=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Action = "Status"
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

workflow Action-VMs
{
    Param
    (
		[Parameter(Mandatory=$true)]
		[Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineListStatus[]]
		$VirtualMachines,
	    [Parameter(Mandatory=$true, HelpMessage="Valid values are 'Status', 'Start' or 'Stop'")]
        [ValidateSet("Status","Start","Stop", ignorecase=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Action = "Status"
    )

    foreach -parallel ($VirtualMachine in $VirtualMachines)
	{
        $VirtualMachineName = $VirtualMachine.Name
        $VirtualMachineId = $VirtualMachine.Id
        $VirtualMachinePowerState = $VirtualMachine.PowerState

        if ($Action -eq "Status")
        {
            InlineScript
            {
                Write-Verbose -Message "Virtual Machine: $Using:VirtualMachineName PowerState: $Using:VirtualMachinePowerState"
            }
        }
        elseif ($Action -eq "Start")
        {
            if ($($VirtualMachine.PowerState) -ne "VM running")
            {
                InlineScript
                {
                    try
                    {
                        Start-AzureRmVM -Name $Using:VirtualMachineName -Id $Using:VirtualMachineId -ErrorAction Stop
                        Write-Verbose -Message "Starting Virtual Machine $Using:VirtualMachineName"
                    }
                    catch
                    {
                        Write-Error -Message "Unable to start Virtual Machine $Using:VirtualMachineName"
                    }
                }
            }
        }
        elseif ($Action -eq "Stop")
        {
            if ($($VirtualMachine.PowerState) -ne "VM deallocated")
            {
                InlineScript
                {
                    try
                    {
                        Stop-AzureRmVM -Name $Using:VirtualMachineName -Id $Using:VirtualMachineId -ErrorAction Stop -Force
                        Write-Verbose -Message "Stopping Virtual Machine $Using:VirtualMachineName"
                    }
                    catch
                    {
                        Write-Error -Message "Unable to stop Virtual Machine $Using:VirtualMachineName"
                    }
                }
            }
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
        Write-Status -Message “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
        exit
    }
}
else
{
    if ((Invoke-Expression 'whoami') -ne "root")
    {
        Write-Status -Message “You do not have root access to run this script!`nPlease restart PowerShell with sudo!”
        exit
    }
}

# Set PowerShell execution policies
Set-CustomExecutionPolicy -Scope 'LocalMachine' -ExecutionPolicy Unrestricted

# Install pre-requisite PowerShell modules
Install-PowerShellModule -RepositoryName 'PSGallery' -ModuleName 'AzureRM.Resources'

try
{
    $AzureRMUser = Add-AzureRmAccount -ErrorAction Stop
    Write-Status -Message "Logged on as User $($AzureRMUser.Context.Account)"
}
catch
{
    Write-Warning -Message "Unable to connect to Azure AD"
    exit
}

try
{
    $AzureRMSubscriptions = Get-AzureRMSubscription -ErrorAction Stop
    Write-Status -Message "User $($AzureRMUser.Context.Account.Id) has access to $($AzureRMSubscriptions.Count) subscriptions"
}
catch
{
    Write-Warning -Message "Unable to get Azure subscriptions"
}

foreach ($AzureRMSubscription in $AzureRMSubscriptions)
{
    Write-Status -Message "Azure Subscription: $AzureRMSubscription"
    try
    {
        $VirtualMachines = Get-AzureRmVM -Status
        Write-Status -Message "Subscription $($AzureRMSubscription.SubscriptionId) has $($VirtualMachines.Count) Virtual Machines"
        
        #Action-VMs -VirtualMachines $VirtualMachines -Action $Action

        foreach ($VirtualMachine in $VirtualMachines)
        {
            if ($($VirtualMachine.PowerState) -ne "VM running")
            {
                try
                {
                    Start-AzureRmVM -Name $VirtualMachine.Name -Id $VirtualMachine.Id
                    Write-Status -Message "Virtual Machine $VirtualMachine.Name Started"
                }
                catch
                {
                    Write-Status -Message "Unable to start Virtual Machine $($VirtualMachine.Name)"
                }
            }
        }
    }
    catch
    {
        Write-Warning -Message "Unable to get Azure subscriptions"
    }
}
