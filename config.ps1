[hashtable]$script:Config = @{
    BaseUrl    = "https://example.jamfcloud.com" # URL of your Jamf Pro server
    Username   = "username" # Leave empty if using API credentials
    Password   = "password123" # Leave empty if using API credentials
    #clientId     = "00000000-0000-0000-0000-000000000000" # Fill if using API credentials
    #clientSecret = "your-client-secret-here" # Fill if using API credentials
    DataFolder = Join-Path (Get-Location) "JAMF_Backup"
    ApiVersion = "classic" # Use 'v1','v2' or 'classic'
    Token      = $null
}