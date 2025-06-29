<#
.SYNOPSIS
    Functions for Jamf Backup and Restore operations.

.DESCRIPTION
    This script provides functions to obtain and manage Jamf API tokens, make API calls, download Jamf objects, format XML files, and handle file system operations.
    It uses an explicit configuration hashtable ($Config) to pass required parameters, reducing reliance on global state.

.NOTES
    File Name      : JamfBackupRestoreFunctions.ps1
    Author         : Jorge Suarez
    Prerequisite   : PowerShell
    Dependencies   : Requires access to Jamf Pro API
    Version        : 0.1.4
    Contributors   : Cyril Niklaus, wewenttothemoon

.COMPONENT
    Jamf Pro API Integration

.ROLE
    System Administration
    Backup Management
    API Integration

.FUNCTIONALITY
    - Jamf API token management
    - API request handling
    - Object backup and restoration
    - XML file formatting
    - File system operations
#>
function Get-JamfToken {
    # Function to get a Jamf authentication token using either OAuth or Basic auth
    param (
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl = $Config.BaseUrl, # Base URL of the Jamf instance
        [string]$Username = $Config.Username, # Username for Basic auth
        [string]$Password = $Config.Password, # Password for Basic auth
        [string]$ClientId = $Config.ClientId, # Client ID for OAuth
        [string]$ClientSecret = $Config.ClientSecret  # Client secret for OAuth
    )

    Write-Host "PSJamfBackupRestore 🚀`n" -ForegroundColor Green

    Write-Host "BaseUrl: [$BaseUrl]" -ForegroundColor Green

    if ($ClientId -and $ClientSecret) {
        Write-Host "ClientId: [$ClientId]" -ForegroundColor Green
        Write-Host "ClientSecret: [REDACTED]" -ForegroundColor Green
        # Use OAuth authentication if client credentials are provided
        $tokenUrl = "$BaseUrl/api/oauth/token"
        $body = "client_id=$ClientId"
        $body += "&client_secret=$ClientSecret"
        $body += "&grant_type=client_credentials"
        $headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }
    } elseif ($Username -and $Password) {
        Write-Host "Username: [$Username]" -ForegroundColor Green
        Write-Host "Password: [REDACTED]" -ForegroundColor Green
        # Use Basic authentication if username/password are provided
        $tokenUrl = "$BaseUrl/api/v1/auth/token"
        $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Username):$($Password)"))
        $headers = @{
            "Authorization" = "Basic $base64Auth"
            "Accept"        = "application/json"
        }
    } else {
        throw "Must provide either Username/Password or ClientId/ClientSecret."
    }

    Write-Host "Obtaining Jamf API token..." -ForegroundColor Cyan -NoNewline

    try {
        # Make the token request
        $tokenSplat = @{
            Uri             = $tokenUrl
            Method          = 'Post'
            Body            = $body
            Headers         = $headers
            UseBasicParsing = $true
        }
        $response = Invoke-WebRequest @tokenSplat
        # Extract token from response, handling both OAuth and Basic auth response formats
        $token = ($response.Content | ConvertFrom-Json).PSObject.Properties["access_token", "token"].Where({ $_.Value }).Value
        # Output welcome message with config settings and credentials redacted

        Write-Host " - ✅"
        return $token
    } catch {
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Host " - ❌ Unauthorized access. Check your credentials." -ForegroundColor Red
        } else {
            throw "Unexpected Error: $_"
        }
    }
}
function Test-AndRenewAPIToken {
    # Function to test if current API token is valid and renew if needed
    param (
        [string]$BaseUrl = $Config.BaseUrl,
        [string]$ApiVersion = "v1",
        [string]$Token = $Config.Token
    )

    try {
        # Attempt to keep the current token alive
        $keepAliveSplat = @{
            BaseUrl    = $BaseUrl
            ApiVersion = $ApiVersion
            Endpoint   = "auth/keep-alive"
            Method     = "POST"
            Token      = $Token
        }
        $response = Invoke-JamfApiCall @keepAliveSplat
        # If successful, update the token in config
        if ($response.token) {
            $Config.Token = $response.token
        } else {
            throw "No token returned from keep-alive request."
        }
    } catch {
        # If keep-alive fails, get a new token
        Write-Host "Attempting to refresh token..."
        $Config.Token = Get-JamfToken -BaseUrl $BaseUrl
    }
}
function Invoke-JamfApiCall {
    # Function to make API calls to Jamf Pro
    param (
        [string]$BaseUrl = $Config.BaseUrl,
        [string]$ApiVersion = $Config.ApiVersion,
        [string]$Endpoint,
        [string]$Method = "GET",
        [string]$Body,
        [string]$Token = $Config.Token,
        [switch]$XML
    )

    # Validate token exists
    if (-not $Token) { throw "No token provided." }

    # Build the full API URL
    $urlSplat = @{
        BaseUrl    = $BaseUrl
        ApiVersion = $ApiVersion
        Endpoint   = $Endpoint
    }
    $fullUrl = Get-JamfApiUrl @urlSplat

    # Set content type based on XML switch
    $contentType = if ($XML) { "application/xml" } else { "application/json" }
    $accept = if ($XML) { "text/xml" } else { "application/json" }

    # Prepare request headers
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = $contentType
        "Accept"        = $accept
    }

    # Build API request parameters
    $apiSplat = @{
        URI             = $fullUrl
        Method          = $Method
        Headers         = $headers
        UseBasicParsing = $true
    }
    
    # Add body if provided
    if ($Body) {
        $apiSplat.Add("Body", $Body)
    }

    try {
        # Make the API request
        $response = Invoke-WebRequest @apiSplat

        # Return response based on format
        if ($XML) {
            return $response.Content
        } else {
            return ($response.Content | ConvertFrom-Json)
        }
    } catch {
        # Handle token expiration
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Host "Token expired. Renewing token..."
            $Config.Token = Get-JamfToken -BaseUrl $BaseUrl
            $headers["Authorization"] = "Bearer $Config.Token"
            $apiSplat["Headers"] = $headers

            try {
                # Retry request with new token
                $response = Invoke-WebRequest @apiSplat

                if ($XML) {
                    return $response.Content
                } else {
                    return ($response.Content | ConvertFrom-Json)
                }
            } catch {
                throw "API Error ($Method $fullUrl): $_"
            }
        } else {
            throw "API Error ($Method $fullUrl): $_"
        }
    }
}
function Get-JamfApiUrl {
    # Function to construct Jamf API URLs based on version and endpoint
    param (
        [string]$BaseUrl, # Base URL of the Jamf instance
        [string]$ApiVersion, # API version to use (v1, v2, v3, or classic)
        [string]$Endpoint      # API endpoint to call
    )
    # Return appropriate URL format based on API version
    switch ($ApiVersion) {
        "v1" { "$BaseUrl/api/v1/$Endpoint" }      # Modern v1 API format
        "v2" { "$BaseUrl/api/v2/$Endpoint" }      # Modern v2 API format 
        "v3" { "$BaseUrl/api/v3/$Endpoint" }      # Modern v3 API format
        "classic" { "$BaseUrl/JSSResource/$Endpoint" }  # Legacy API format
        default { throw "Invalid ApiVersion. Use 'v1', 'v2', or 'classic'." }
    }
}
function Format-XML {
    param (
        [string]$FilePath, # Path to the input XML file
        [string]$OutputPath = $FilePath    # Path for the formatted output, defaults to input path
    )

    try {
        # Read the entire file as a single string
        $content = Get-Content -Path $FilePath -Raw

        # Remove any non-printable characters except tab, newline, and carriage return
        $cleanContent = $content -replace '[^\x09\x0A\x0D -~]', ''

        # Convert the cleaned string to XML object
        $xml = [xml]$cleanContent

        # Create XML writer with UTF-8 encoding
        $xmlWriter = New-Object System.Xml.XmlTextWriter($OutputPath, [System.Text.Encoding]::UTF8)

        # Configure writer to use indented format
        $xmlWriter.Formatting = [System.Xml.Formatting]::Indented
        $xmlWriter.Indentation = 4    # Set indent to 4 spaces

        # Save the formatted XML to file
        $xml.Save($xmlWriter)

        # Clean up by closing the writer
        $xmlWriter.Close()
    } catch {
        Write-Error "Failed to format XML: $_"
    }
}
function Ensure-DirectoryExists {
    # Creates a directory if it doesn't exist
    param (
        [string]$DirectoryPath
    )
    if (-not (Test-Path $DirectoryPath)) {
        New-Item -Path $DirectoryPath -ItemType Directory -Force | Out-Null
    }
}
function Get-SanitizedDisplayName {
    # Sanitizes object names by replacing non-alphanumeric chars with underscores
    param (
        [string]$Id,
        [string]$Name
    )
    $sanitizedName = $Name -replace '[^\x30-\x39\x41-\x5A\x61-\x7A]+', '_'
    return "$($id)_$sanitizedName"
}
function Download-JamfObject {
    # Downloads and saves Jamf objects with their associated files
    param (
        [string]$Id,
        [string]$Resource,
        [string]$DownloadDirectory
    )

    try {
        # Validate token status before proceeding
        Test-AndRenewAPIToken -BaseUrl $Config.BaseUrl -Token $Config.Token
        
        # Get object details from Jamf
        $jamfObject = Get-JamfObject -Id $Id -Resource $Resource
        $extension = if ($Resource -eq "computer-prestages") { "json" } else { "xml" }
        $displayName = Get-SanitizedDisplayName -Id $Id -Name $jamfObject.name

        # Define resources that can be organized by site
        $siteBasedResources = @(
            "computergroups",
            "computers",
            "macapplications",
            "mobiledeviceapplications",
            "mobiledeviceconfigurationprofiles",
            "mobiledevicegroups",
            "osxconfigurationprofiles",
            "policies",
            "restrictedsoftware"
        )

        $subfolder = ""
        $targetDir = $DownloadDirectory  # default target directory

        if ($jamfObject.plist) {
            # Parse XML content
            [xml]$xml = $jamfObject.plist

            # Set subfolder based on group type (smart vs static)
            if ($Resource -in @("computergroups", "mobiledevicegroups")) {
                $subfolder = if ($xml.SelectSingleNode("//is_smart").InnerText -eq 'true') { "smart" } else { "static" }
            } 
            # Organize by site if applicable
            elseif ($siteBasedResources -contains $Resource) {
                $siteName = switch ($Resource) {
                    "computergroups" { $xml.computer_group.site.name }
                    "computers" { $xml.computer.general.site.name }
                    "macapplications" { $xml.mac_application.general.site.name }
                    "mobiledeviceapplications" { $xml.mobile_device_application.general.site.name }
                    "mobiledeviceconfigurationprofiles" { $xml.mobile_device_configuration_profile.general.site.name }
                    "mobiledevicegroups" { $xml.mobile_device_group.site.name }
                    "osxconfigurationprofiles" { $xml.os_x_configuration_profile.general.site.name }
                    "policies" { $xml.policy.general.site.name }
                    "restrictedsoftware" { $xml.restricted_software.general.site.name }
                }

                # Set site-based subfolder if site exists and isn't 'NONE'
                if (-not [string]::IsNullOrWhiteSpace($siteName)) {
                    $subfolder = if ($siteName -ne 'NONE') { $siteName }
                }
            }

            # Create and use subfolder if specified
            if ($subfolder) {
                $targetDir = Join-Path -Path $DownloadDirectory -ChildPath $subfolder
            }

            # Save plist file
            Ensure-DirectoryExists -DirectoryPath $targetDir
            $plistFilePath = Join-Path -Path $targetDir -ChildPath "$displayName.plist"
            $jamfObject.plist | Out-File -FilePath $plistFilePath -Encoding utf8
            Format-XML -FilePath $plistFilePath
        }

        # Save payload file if it exists
        if ($jamfObject.payload) {
            Ensure-DirectoryExists -DirectoryPath $targetDir
            $payloadFilePath = Join-Path -Path $targetDir -ChildPath "$displayName.$extension"
            $jamfObject.payload | Out-File -FilePath $payloadFilePath -Encoding utf8
            if ($extension -eq "xml") {
                Format-XML -FilePath $payloadFilePath
            }
        }

        # Save script content if it exists
        if ($jamfObject.script) {
            # Remove .sh extension if present in display name
            if ($displayName -like "*.sh") {
                $displayName = $displayName -replace '\.sh$', ''
            }

            $scriptFilePath = Join-Path -Path $DownloadDirectory -ChildPath "$displayName.sh"
            $jamfObject.script | Out-File -FilePath $scriptFilePath -Encoding utf8
        }
    } catch {
        Write-Error "Error downloading $Resource : ID $Id - $_"
    }
}
function Get-JamfObject {
    param (
        [string]$Id, # Unique identifier of the Jamf object
        [string]$Resource   # Type of resource (e.g., policies, scripts, computer-prestages)
    )

    # Determine API version - computer-prestages uses v3, others use classic API
    $apiVersion = if ($Resource -eq "computer-prestages") { "v3" } else { "classic" }
    
    # Build endpoint URL - computer-prestages has different format than other resources
    $endpoint = if ($Resource -eq "computer-prestages") { "$Resource/$Id" } else { "$Resource/id/$Id" }
    
    # Make API call - use XML format for classic API, JSON for v2/v3
    $response = Invoke-JamfApiCall -Endpoint $endpoint -Method "GET" -ApiVersion $apiVersion -XML:($apiVersion -eq "classic")

    # Handle modern API responses (v2/v3)
    if ($apiVersion -match "v2|v3") {
        return @{
            name    = $response.displayName    # Get display name from response
            payload = $response | ConvertTo-Json -Depth 5  # Convert response to JSON
        }
    } 
    # Handle classic API responses
    else {
        $xml = [xml]$response  # Convert response to XML object
        $payload = $xml.DocumentElement.FirstChild.payloads  # Extract payloads
        $name = $xml.SelectSingleNode("//name").InnerText   # Get object name

        # Extract script content if it's a script-related resource
        $script = if ($Resource -eq "scripts") { 
            $xml.SelectSingleNode("//script_contents").InnerText 
        } elseif ($Resource -eq "computerextensionattributes") { 
            $xml.SelectSingleNode("//input_type/script").InnerText 
        } else { 
            $null 
        }

        # Return structured data including name, payload, original XML, and script content
        return @{
            name    = $name
            payload = $payload
            plist   = $response 
            script  = $script
        }
    }
}
function Download-JamfObjects {
    param(
        [string]$Id, # Optional: Specific object ID to download
        [string]$Resource, # Required: Type of Jamf resource (e.g., policies, scripts)
        [switch]$ClearExports       # Optional: Clear existing exports before downloading
    )

    # Construct the download directory path using the resource type
    $downloadDirectory = Join-Path -Path $Config.DataFolder -ChildPath $Resource

    # If ClearExports is specified, remove existing directory and its contents
    if ($ClearExports -and (Test-Path $downloadDirectory)) { Remove-Item $downloadDirectory -Recurse -Force }
    # Create the download directory if it doesn't exist
    Ensure-DirectoryExists -DirectoryPath $downloadDirectory

    if ($Id) {
        # Download a single object if ID is provided
        Download-JamfObject -Id $Id -Resource $Resource -DownloadDirectory $downloadDirectory
    } else {
        # Download all objects of the specified resource type
        Write-Host "Exporting all [$Resource] objects" -NoNewline -ForegroundColor Cyan
        # Get all object IDs for the specified resource
        $objectIds = Get-JamfObjectIds -Resource $Resource
        try {
            foreach ($objectId in $objectIds) {
                # Verify token is valid before each download
                Test-AndRenewAPIToken -BaseUrl $Config.BaseUrl -Token $Config.Token
            
                # Download each object individually
                Download-JamfObject -Id $objectId -Resource $Resource -DownloadDirectory $downloadDirectory
            }
            Write-Host " - ✅" -ForegroundColor Green
        } catch {
            Write-Host " - ❌" -ForegroundColor Red
            Write-Error "Failed to download objects for resource '$Resource': $_"
        }

    }
}
function Get-JamfObjectIds {
    param (
        [string]$Resource
    )

    # Invoke the Jamf API call to get the response
    $apiVersion = switch ($Resource) {
        "computer-prestages" { "v3" }
        "patch-software-title-configurations" { "v2" }
        default { "classic" }
    }
    $response = Invoke-JamfApiCall -Endpoint $Resource -Method "GET" -ApiVersion $ApiVersion

    if (-not $response) {
        Write-Host "No response received for resource: $Resource" -ForegroundColor Red
        return $null
    }

    # Get the first NoteProperty from the response
    $firstProperty = $response | Get-Member -MemberType NoteProperty | Select-Object -First 1

    if (-not $firstProperty) {
        Write-Host "No NoteProperties found in response for resource: $Resource" -ForegroundColor Yellow
        return $null
    }

    # Extract the value of the first NoteProperty and get the IDs
    $objects = $response.$($firstProperty.Name)

    # Uncomment if you want to export smart groups along with static groups
    # if ($Resource -in "computergroups", "mobiledevicegroups") {
    #     return ($objects | Where-Object { -not $_.is_smart }).id
    # }

    # For computer-prestages, the property is 'results' with a nested structure
    if ($Resource -eq "computer-prestages") {
        return $objects.id
    }

    # Default case: return the IDs directly from the first NoteProperty
    return $objects.id
}
function Invalidate-JamfToken {
    # Function to invalidate/revoke a Jamf API token
    param (
        [string]$BaseUrl = $Config.BaseUrl, # Base URL of the Jamf instance
        [string]$ApiVersion = "v1", # API version to use
        [string]$Token = $Config.Token           # Token to invalidate
    )

    # Validate token exists
    if (-not $Token) {
        Write-Host "Token is required to invalidate." -ForegroundColor Red
        return $false
    }

    try {
        # Make API call to invalidate token endpoint
        $tokenSplat = @{
            BaseUrl    = $BaseUrl
            ApiVersion = $ApiVersion
            Endpoint   = "auth/invalidate-token"
            Method     = "POST"
            Token      = $Token
        }
        $response = Invoke-JamfApiCall @tokenSplat
        
        # Check response - null indicates successful invalidation
        if ($null -eq $response) {
            Write-Host "Token successfully invalidated." -ForegroundColor Green
        } else {
            Write-Host "Unexpected response: $response" -ForegroundColor Yellow
        }
    } catch {
        # Handle error cases
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Host "Token already invalid or unauthorized." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to invalidate token: $_" -ForegroundColor Red
        }
    }
}
function Upload-JamfObject {
    [CmdletBinding()]
    param (
        # The Jamf resource name (e.g., "policies", "scripts", etc.)
        [Parameter(Mandatory = $true)]
        [string]$Resource,

        # Path to the file containing the object payload to upload.
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        # (Optional) The ID of an existing object. If provided with -Update, an update (PUT) is performed.
        [string]$Id,

        # If provided (with $Id), this switch indicates that the object should be updated rather than created.
        [switch]$Update,

        # Optional parameters that default from the configuration hashtable.
        [string]$ApiVersion = $Config.ApiVersion,
        [string]$BaseUrl = $Config.BaseUrl,
        [string]$Token = $Config.Token
    )

    # Read the payload from the file.
    try {
        $payload = Get-Content -Path $FilePath -Raw
    } catch {
        throw "Failed to read file '$FilePath': $_"
    }

    # Determine if the payload is XML or JSON by checking its first non-whitespace character.
    $trimmedPayload = $payload.TrimStart()
    $isXML = $trimmedPayload.StartsWith("<")

    # Determine the API endpoint and HTTP method based on whether this is an update or a new upload.
    if ($Update -and $Id) {
        $endpoint = "$Resource/id/$Id"
        $method = "PUT"
    } else {
        $endpoint = "$Resource/id/0"
        $method = "POST"
    }

    # Use the Invoke-JamfApiCall helper function to perform the upload.
    try {
        $params = @{
            BaseUrl    = $BaseUrl
            ApiVersion = $ApiVersion
            Endpoint   = $endpoint
            Method     = $method
            Body       = $payload
            Token      = $Token
            XML        = $isXML
        }
        $response = Invoke-JamfApiCall @params
        Write-Output "Upload successful. Response:" 
        return $response
    } catch {
        throw "Error uploading Jamf object to resource '$Resource': $_"
    }
}
function Upload-JamfObjects {
    [CmdletBinding()]
    param(
        # The Jamf resource type to upload (e.g., "policies", "scripts", etc.)
        [Parameter(Mandatory = $true)]
        [string]$Resource,

        # Directory containing the objects to upload
        [Parameter(Mandatory = $false)]
        [string]$SourceDirectory = (Join-Path (Get-Location) "$($Config.DataFolder)/$Resource"),

        # File pattern to match (defaults to XML files)
        [Parameter(Mandatory = $false)]
        [string]$FilePattern = "*.xml",

        # If specified, only upload objects with these IDs
        [Parameter(Mandatory = $false)]
        [string[]]$Ids,

        # Whether to update existing objects
        [Parameter(Mandatory = $false)]
        [switch]$Update
    )

    # Verify source directory exists
    if (-not (Test-Path $SourceDirectory)) {
        Write-Error "Source directory not found: $SourceDirectory"
        return
    }

    # Get all files matching the pattern
    $files = Get-ChildItem -Path $SourceDirectory -Filter $FilePattern

    foreach ($file in $files) {
        # Extract ID from filename (assumes format: "ID_Name.xml")
        $idMatch = $file.BaseName -match '^(\d+)_'
        $id = if ($idMatch) { $matches[1] } else { $null }

        # Skip if we're filtering by IDs and this one isn't in the list
        if ($Ids -and $id -notin $Ids) {
            continue
        }

        Write-Host "Processing $($file.Name)..." -ForegroundColor Cyan

        try {
            $params = @{
                Resource = $Resource
                FilePath = $file.FullName
            }

            if ($Update -and $id) {
                $params['Id'] = $id
                $params['Update'] = $true
            }

            Upload-JamfObject @params
            Write-Host "Successfully uploaded $($file.Name)" -ForegroundColor Green
        } catch {
            Write-Error "Failed to upload $($file.Name): $_"
        }
    }
}
function Invoke-GitPush {
    git add .
    $commitMessage = "Manual-Commit on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    git commit -m $commitMessage

    # Push changes to the repository
    git push origin main

    Write-Output "Changes pushed to Repo."
} # Invoke-GitPush