<#
.SYNOPSIS
Updates a Jamf API role with required Create, Read, and Update privileges.

.DESCRIPTION
This script retrieves all available privileges from the Jamf API and filters them to include only those objects that have Create, Read, and Update capabilities. It then updates a specified API role with these filtered privileges.

.PARAMETER apiRoleName
The name of the API role to update. Default is "BackupRestoreClient".

.NOTES
Requires:
- config.ps1 file in the same directory containing Jamf API configuration
- JamfBackupRestoreFunctions.ps1 file containing required functions
- Valid Jamf Pro API credentials

.EXAMPLE
.\AddApiRolePrivileges.ps1

.FUNCTIONALITY
- Authenticates with Jamf Pro API
- Retrieves and validates existence of specified API role
- Gets all available API privileges
- Filters privileges to include only objects with Create, Read, and Update capabilities
- Updates the specified role with filtered privileges
- Provides feedback on the update operation

.OUTPUTS
Displays status messages about the operation progress and results, including:
- Role validation
- Update status
- Count and list of applied privileges

.NOTES
Author: Jorge Suarez

#>

$apiRoleName = "BackupRestoreClient" # Name of the role to update

. (Join-Path (Get-Location) "config.ps1")
. (Join-Path (Get-Location) "JamfBackupRestoreFunctions.ps1")

$script:Config.Token = Get-JamfToken -Config $script:Config

# Find the BackupRestoreRole ID
$roles = Invoke-JamfApiCall -endpoint "api-roles" -token $script:Config.Token -ApiVersion "v1"
$role = $roles.results | Where-Object { $_.displayName -eq $apiRoleName  }
if (-not $role) {
    Write-Host "Role '$apiRoleName' not found. Exiting." -ForegroundColor Red
    exit
}
$roleId = $role.id

# Get all available privileges
$allPrivilegesResponse = Invoke-JamfApiCall -endpoint "api-role-privileges" -token $Script:Config.Token -ApiVersion "v1"
if (-not $allPrivilegesResponse) {
    Write-Host "Failed to retrieve privileges list. Exiting." -ForegroundColor Red
    exit
}
$allPrivileges = $allPrivilegesResponse.privileges

# Filter privileges for objects with Create, Read, and Update
$crudPrivileges = @()
$objectNames = $allPrivileges | ForEach-Object { $_ -replace '^(Create|Read|Update|Send|Flush|Delete|View)\s+', '' } | Sort-Object -Unique

foreach ($object in $objectNames) {
    $create = "Create $object"
    $read = "Read $object"
    $update = "Update $object"
    
    if (($allPrivileges -contains $create) -and 
        ($allPrivileges -contains $read) -and 
        ($allPrivileges -contains $update)) {
        $crudPrivileges += $create
        $crudPrivileges += $read
        $crudPrivileges += $update
    }
}

# Prepare the update payload as a JSON string
$updatePayload = @{
    privileges = $crudPrivileges
} | ConvertTo-Json -Depth 10

# Update the role
Write-Host "Updating BackupRestoreRole (ID: $roleId) with required privileges..." -ForegroundColor Cyan
$result = Invoke-JamfApiCall -endpoint "api-roles/$roleId" -token $Script:Config.Token -method "PUT" -body $updatePayload -ApiVersion "v1"
if ($result) {
    Write-Host "BackupRestoreRole updated successfully with $($crudPrivileges.Count) privileges!" -ForegroundColor Green
    Write-Host "Applied privileges: $($crudPrivileges -join ', ')"
} else {
    Write-Host "Failed to update BackupRestoreRole." -ForegroundColor Red
}