# This script sets up the configuration for the Jamf Pro API interaction.
[hashtable]$script:Config = @{
    BaseUrl    = "https://instance.jamfcloud.com" # URL of your Jamf Pro server
    Username   = "username" # Leave empty if using API credentials
    Password   = 'password' # Leave empty if using API credentials
    #clientId     = "00000000-0000-0000-0000-000000000000" # Fill if using API credentials
    #clientSecret = "your-client-secret-here" # Fill if using API credentials
    DataFolder = Join-Path (Get-Location) "JAMF_Backup_Production\$($(Get-Date -Format 'MM-dd-yyyy'))"
    ApiVersion = "classic" # Use 'v1','v2' or 'classic'
    IconMaxId  = 300 # Maximum IDs for icons to scan/discover, adjust as needed
    Token      = $null
}