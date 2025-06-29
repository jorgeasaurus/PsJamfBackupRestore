
# Usage Example: 
. (Join-Path (Get-Location) "config.ps1")
. (Join-Path (Get-Location) "JamfBackupRestoreFunctions.ps1")

if ($null -eq $script:Config) {
    throw "Config is not initialized."
}

# Request a Jamf token
$tokenParams = @{
    Username = $script:Config.Username
    Password = $script:Config.Password
    BaseUrl  = $script:Config.BaseUrl
}

$script:Config.Token = Get-JamfToken @tokenParams

# Download multiple resource objects from Jamf Pro
@(
    "osxconfigurationprofiles",
    "mobiledeviceconfigurationprofiles",
    "scripts",
    "restrictedsoftware", 
    "policies", 
    "computer-prestages", 
    "computerextensionattributes",
    "computergroups",
    "mobiledevicegroups", 
    "mobiledeviceextensionattributes", 
    "departments",
    "buildings",
    "categories",
    "computers",
    "mobiledevices",
    "mobiledeviceapplications",
    "macapplications"
) | ForEach-Object {
    Download-JamfObjects -resource $_ -ClearExports
}

# Download a single object from Jamf Pro
Download-JamfObject -ID "3" -Resource "osxconfigurationprofiles"

# Upload an updated object back into Jamf Pro
Upload-JamfObject `
    -Token $script:Config.Token `
    -FilePath "$($script:Config.DataFolder)/osxconfigurationprofiles/9_Browser_Profile_Settings.xml" `
    -Resource "osxconfigurationprofiles" `
    -Id "9" `
    -Update

#Upload an updated policy object into Jamf Pro 
Upload-JamfObject `
    -Token $script:Config.Token `
    -Resource "policies" `
    -FilePath "$($script:Config.DataFolder)/policies/3_Google_Chrome.xml" `
    -Id "3" `
    -Update

# Upload a new category object into Jamf Pro 
Upload-JamfObject `
    -Token $script:Config.Token `
    -FilePath "$($script:Config.DataFolder)/categories/Security.xml" `
    -Resource "categories"

# Upload all policies from backup
Upload-JamfObjects -Resource "policies"

# Update specific policies by ID
Upload-JamfObjects -Resource "departments" -Ids @(1, 2) -Update

# Upload and update existing objects
Upload-JamfObjects -Resource "buildings" -Update

# Upload from a custom directory
Upload-JamfObjects -Resource "policies" -SourceDirectory (Join-Path (Get-Location) "CustomBackup/policies")

# Revoke Token
Invalidate-JamfToken -Token $script:Config.Token