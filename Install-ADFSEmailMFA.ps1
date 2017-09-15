$ADFSEmailMFAPath = Read-Host -Prompt "Please input the path to the ADFSEmailMFA.dll file."
$JsonPath = Read-Host -Prompt "Please input the path to the Newtonsoft Json DLL file."

[System.Reflection.Assembly]::Load("System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
$publisher = New-Object System.EnterpriseServices.Internal.Publish

# For installation 
$publisher.GacInstall("$ADFSEmailMFAPath")
$publisher.GacInstall("$JsonPath")

$typeName = "ADFSEmailMFA.EmailAuthenticationProvider, ADFSEmailMFA, Version=1.0.0.0, Culture=neutral, PublicKeyToken=27dfac78803075cc”

Unregister-AdfsAuthenticationProvider -Name "Email MFA Method" -Confirm
Register-AdfsAuthenticationProvider -TypeName $typename -Name "Email MFA Method" -ConfigurationFilePath E:\ADFSEmailMFA\ADFSMFAConfig.json
Restart-Service ADFSSRV