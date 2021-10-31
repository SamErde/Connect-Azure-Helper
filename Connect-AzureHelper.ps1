<#
.SYNOPSIS
Quickly connect remote PowerShell sessions for Azure and Office 365 services.

.DESCRIPTION
Connect remote PowerShell sessions for Azure and Office 365 services using modern authentication 
with MFA. This was created initially to make it easier to connect to GCC High tenant services, but
can p;be expanded to offer parameters for commercial, government, or foreign tenants.

.PARAMETER TenantType
Specifies the tenant type. Options may include commercial, government, GCC High, DoD, Germany, and China.

.NOTES
Author:     Sam Erde
Contact:
            Twitter:    https://twitter.com/SamErde
            GitHub:     https://github.com/SamErde

Version:    0.9
Created:    2021-10-27
Purpose:    Initial script development

Tasks:      [] Wrap in functions
            [] Add parameters for service[s] to connect to
            [] Add parameters for environment types to connect to

References:

    Connect to Exchange Online PowerShell:
    https://docs.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell

    Connect to Exchange Online Protection:
    https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps
    https://docs.microsoft.com/en-us/powershell/module/exchange/connect-ippssession?view=exchange-ps

    Connect to Security and Compliance Center:
    https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell
    https://docs.microsoft.com/en-us/powershell/module/exchange/connect-ippssession?view=exchange-ps
#>

#region XML configuration and variables WIP
# Create XML file with details about different Azure environment types and regions
# Use XML as reference for URIs and AAD authentication points to keep this script clean
$ConfigFile = Get-Content "environments.xml"
$Environments = $ConfigFile.environments
$Services = $ConfigFile.services
#endregion XML configuration and variables WIP

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false -Force

# Import the ExchangeOnlineManagement PowerShell Module
if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
    Import-Module -Name ExchangeOnlineManagement
}
else {
    Write-Warning "The ExchangeOnlineManagement module is not yet installed. Attempting to install now."
    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser
    Import-Module -Name ExchangeOnlineManagement
}


# Prompt admin for their Azure management account UPN if it is not already specified.
if (!($Upn)) { 
    $Upn = Read-Host -Prompt "Please enter the UPN of your Azure management account"
}

# Specifying the Azure AD authorization endpoint URI for non-commercial tenants saves you from being redirected the relevant login page.
$AadAuthEndpointUri = "https://login.microsoftonline.us/common"


# Check to see if Basic Auth is enabled or not. This is required to send the OAuth token because WinRM does not support OAuth.
$WinRmBasicAuth = Get-Item -Path 'WSMan:\localhost\Client\Auth\Basic'
if (!($WinRmBasicAuth.Value -eq 'true')) {
    
    if (!([Security.Principal.WindowsIdentity]::GetCurrent().Owner.IsWellKnown("BuiltInAdministratorsSid"))) {
        Write-Warning "Basic Authentication for the WinRM Client is currently disabled, and Administrator privileges are required to enable it. `nBasic Authentication is not used, but is required to send the OAuth token because WinRM does not support OAuth."
        Break
    }

    # Warn the operator if Basic Auth is turned off by group policy.
    if ($WinRmBasicAuth.SourceOfValue -eq 'GPO') {
        Write-Warning -Message "Basic Authentication for the WinRM client is disabled by a GPO. This script will change the registry setting directly as a temporary workaround. `nPlease note that the setting will be over-written during the next GPO refresh cycle."
    }
    # Set the value and show the result.
    $WinRmBasicAuthOldValue = $WinRmBasicAuth
    Set-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Value 1
    $WinRmBasicAuth = Get-Item -Path 'WSMan:\localhost\Client\Auth\Basic'
    Write-Output "The old Basic Auth enabled value was $($WinRmBasicAuthOldValue.Value) and the new value is $($WinRmBasicAuth.Value)."
}


<#  NOTE: POSSIBLY MEMORY LEAKS
    The latest version of EXO V2 module and frequent use of the Connect-ExchangeOnline and 
    Disconnect-ExchangeOnline cmdlets in a single PowerShell session or script might lead to a 
    memory leak. The best way to avoid this issue is to use the CommandName parameter on the 
    Connect-ExchangeOnline cmdlet to limit the cmdlets that are used in the session.
#>
<#  NOTE: AVOID SESSION LIMITS
    Be sure to disconnect the remote PowerShell session when you're finished. If you close the 
    Windows PowerShell window without disconnecting the session, you could use up all the remote
    PowerShell sessions available to you, and you'll need to wait for the sessions to expire. To
    disconnect the remote PowerShell session, run the following command.

        Disconnect-ExchangeOnline
#>

#region Connection Strings
# ------------------------

# Exchange Online
Connect-ExchangeOnline -UserPrincipalName $upn -ExchangeEnvironmentName O365USGovGCCHigh

# Exchange Online Protection (CONNECTION TAKES A LONG TIME FOR ME)
Connect-IPPSSession -UserPrincipalName $Upn -ConnectionUri https://ps.protection.office365.us/powershell-liveid/ -AzureADAuthorizationEndpointUri $AadAuthEndpointUri

# Security and Compliance Center
Connect-IPPSSession -UserPrincipalName $Upn -ConnectionUri https://ps.compliance.protection.office365.us/powershell-liveid/ -AzureADAuthorizationEndpointUri $AadAuthEndpointUri

# ---------------------------
#endregion Connection Strings

# Disconnect-ExchangeOnline
