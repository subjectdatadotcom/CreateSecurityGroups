<#
.SYNOPSIS
Creates and manages Azure AD security groups and mail-enabled security groups by processing user and group mapping data, ensuring proper membership and ownership assignments during tenant migrations or provisioning tasks.

.DESCRIPTION
This script automates the creation and updating of security groups in Azure AD and Exchange Online. It processes user and group data from CSV reports, maps users between source and target tenants using a provided mapping file, and creates new groups or updates existing ones based on ownership and membership data. The script distinguishes between regular security groups and mail-enabled security groups, handles orphaned users, and ensures users are only added if not already members. All actions are logged in detailed reports, including any unmapped users.

The script supports:
- User and group mapping from legacy (source) to new (target) environments
- Creating new Azure AD or mail-enabled security groups with correct attributes
- Assigning owners and members while preventing duplicates
- Exporting reports for newly created and updated groups
- Tracking unmapped users for remediation

.NOTES
Requires administrative access to Azure AD and Exchange Online. The AzureAD and ExchangeOnlineManagement modules must be installed and connected. Intended for IT admins performing group provisioning or tenant-to-tenant migrations.

.AUTHOR
SubjectData

.EXAMPLE
.\CreateSecurityGroups.ps1
Processes group data from input files and provisions Azure AD and mail-enabled security groups accordingly, exporting mapping reports and logging unmapped users.
#>

# Ensure the Exchange Management Shell module is loaded
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module -Name ExchangeOnlineManagement -Force
    Import-Module ExchangeOnlineManagement
} else {
    Import-Module ExchangeOnlineManagement
}

$AzureADModule = "AzureAD"

# Check if the module is already installed
if (-not(Get-Module -Name $AzureADModule -ListAvailable)) {
    # Install the module
    Install-Module -Name $AzureADModule -Force
}

# Import the module
Import-Module $AzureADModule -Force

$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ReportsPath = "$myDir\"


# Paths to the input files
$reportCsvPath = $ReportsPath + "report.csv"
$mappingsCsvPath = $ReportsPath + "mappings.csv"
$preparedCsvPath = $ReportsPath + "Reports\To_be_Created_security_groups.csv"
$newGroupsCsvPath = $ReportsPath + "Reports\created_new_groups.csv"


# Step 1: Read report.csv and mappings.csv
$reportData = Import-Csv -Path $reportCsvPath
$mappingsData = Import-Csv -Path $mappingsCsvPath

# Create a dictionary for fast lookup of Trader emails from Teranet emails (case-insensitive)
$mappingDict = @{}
foreach ($mapping in $mappingsData) {
    $mappingDict[$mapping.TeranetEmail.ToLower()] = $mapping.TraderEmail
}

# Step 2: Prepare the updated data for Trader tenant and write to a new file
$preparedData = @()
$newGroupsData = @()
$unmappedUsers = @()  # Collect unmapped users for logging

foreach ($row in $reportData) {
    $newOwners = $row.Owners
    $newMembers = $row.Members
  $unmappedOwners = @()
  $unmappedMembers = @()
    
    # If OwnersCount > 0, replace Owners with Trader emails
    if ($row.OwnersCount -gt 0 -and $null -ne $row.Owners -and $row.Owners.Trim() -ne "") {
        $owners = $row.Owners -split ";"
        $newOwners = ($owners | ForEach-Object {
            $email = $_.Trim().ToLower()  # Make email case-insensitive
            if ($mappingDict.ContainsKey($email)) {
                $mappingDict[$email]
            } else {
                $unmappedUsers += $email  # Log the unmapped email
              $unmappedOwners += $email  # Collect unmapped owners
                $null  # Skip unmapped users
            }
        }) -join ";"
        $newOwners = $newOwners -replace "(;;|^;|;$)", ""  # Remove leading, trailing, and consecutive semicolons
    } else {
        $newOwners = ""
    }

    # If MembersCount > 0, replace Members with Trader emails
    if ($row.MembersCount -gt 0 -and $null -ne $row.Members -and $row.Members.Trim() -ne "") {
        $members = $row.Members -split ";"
        $newMembers = ($members | ForEach-Object {
            $email = $_.Trim().ToLower()  # Make email case-insensitive
            if ($mappingDict.ContainsKey($email)) {
                $mappingDict[$email]
            } else {
                $unmappedUsers += $email  # Log the unmapped email
              $unmappedMembers += $email  # Collect unmapped members
                $null  # Skip unmapped users
            }
        }) -join ";"
        $newMembers = $newMembers -replace "(;;|^;|;$)", ""  # Remove leading, trailing, and consecutive semicolons
    } else {
        $newMembers = ""
    }

    # Add the modified row to prepared data
    $preparedData += New-Object PSObject -Property @{
        MembersCount  = $row.MembersCount
        GroupGUID     = $row.GroupGUID
        Owners        = $newOwners
        GroupName     = $row.GroupName
        GroupType     = $row.GroupType
        Members       = $newMembers
        OwnersCount   = $row.OwnersCount
      UnmappedOwners  = ($unmappedOwners -join ";")  # Join unmapped owners with semicolon
      UnmappedMembers = ($unmappedMembers -join ";")  # Join unmapped members with semicolon
    }
}

# Export the updated data to a new CSV file for reference
if ($preparedData.Count -gt 0) 
{
    $preparedData | Export-Csv -Path $preparedCsvPath -NoTypeInformation
}

<#
# Step 3: Output any unmapped users to the PowerShell console
if ($unmappedUsers.Count -gt 0) {
    Write-Host "The following users were not found in the mappings:"
    $unmappedUsers | Sort-Object | Get-Unique | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "All users were successfully mapped!"
}
#>

# After all processing, before or after exporting $newGroupsData to CSV
if ($unmappedUsers.Count -gt 0) {
    # Ensure each email is unique before export
    $uniqueUnmappedUsers = $unmappedUsers | Sort-Object | Get-Unique

    # Prepare data for export
    $unmappedUsersExport = @()
    foreach ($email in $uniqueUnmappedUsers) {
        $unmappedUsersExport += New-Object PSObject -Property @{
            Email = $email
        }
    }

    # Define the path for the unmapped users CSV file
    $unmappedUsersCsvPath = $ReportsPath + "Reports\unmapped_users.csv"

    # Export to CSV
    if ($unmappedUsersExport.Count -gt 0) 
    {
        $unmappedUsersExport | Export-Csv -Path $unmappedUsersCsvPath -NoTypeInformation
        Write-Host "Unmapped users have been exported to $unmappedUsersCsvPath"
    }
} 
else 
{
    Write-Host "All users were successfully mapped!" -ForegroundColor Green
}

# Output a message for confirmation
Write-Host "Prepared CSV has been created and saved to $preparedCsvPath"


# Step 3: Create Security Groups in the Trader tenant
# Note: You will need the AzureAD or MSGraph module to interact with the Azure AD for creating security groups.

# Connect to the Trader tenant (you might need proper permissions for this)
Connect-AzureAD

# To Create Mail Enabled secuirty Groups
Connect-ExchangeOnline

foreach ($group in $preparedData) {
    # Skip the group creation if both OwnersCount and MembersCount are 0
    if ($group.OwnersCount -eq 0 -and $group.MembersCount -eq 0) {
        Write-Host "Skipping group '$($group.GroupName)' because both OwnersCount and MembersCount are 0."
        continue
    }

    # Add "TR-" prefix to group name
    $groupNameWithPrefix = "TR - $($group.GroupName)"
    $groupNameTrimmed = "TR - $($group.GroupName)" -replace '\s+', ''

    # Check if the group already exists
    #$existingGroup = Get-AzureADGroup -Filter "DisplayName eq '$group.GroupName'"
    
    $groupName = $group.GroupName

    # Check in Azure AD
    $existingGroupAAD = Get-AzureADGroup | Where-Object { $_.DisplayName -eq $groupNameWithPrefix }

    # Check in Exchange Online
    $existingGroupMailEnabled = Get-DistributionGroup -Identity $groupNameWithPrefix -ErrorAction SilentlyContinue


    
    if (-not $existingGroupAAD -and -not $existingGroupMailEnabled) {
        
        #NEW LOGIC FOR GROUP TYPE - NEED TO TEST
        switch ($group.GroupType) {
            'Security Group' {
                $securityEnabled = $true
                # Create a new security group
                $newGroup = New-AzureADGroup -DisplayName $groupNameWithPrefix `
                                     -MailNickname $groupNameTrimmed `
                                     -SecurityEnabled $true `
                                     -MailEnabled $false 

                # Add Owners if present
                if ($group.OwnersCount -gt 0 -and $group.Owners -ne "") {
                    $owners = $group.Owners -split ";"
                    foreach ($owner in $owners) {
                        # Use the correct filter to find users by email
                        $ownerUser = Get-AzureADUser -Filter "UserPrincipalName eq '$owner'"
                        if ($ownerUser) {
                            Add-AzureADGroupOwner -ObjectId $newGroup.ObjectId -RefObjectId $ownerUser.ObjectId
                        }
                    }
                }

                # Add Members if present
                if ($group.MembersCount -gt 0 -and $group.Members -ne "") {
                    $members = $group.Members -split ";"
                    foreach ($member in $members) {
                        # Use the correct filter to find users by email
                        $memberUser = Get-AzureADUser -Filter "UserPrincipalName eq '$member'"
                        if ($memberUser) {
                            Add-AzureADGroupMember -ObjectId $newGroup.ObjectId -RefObjectId $memberUser.ObjectId
                        }
                    }
                } # End New Logic
            }
            'Mail-enabled Security Group' {
                # Then create the mail-enabled security group
                $newGroup = New-DistributionGroup -Name $groupNameWithPrefix `
                              -DisplayName $groupNameWithPrefix `
                              -Alias $groupNameTrimmed `
                              -Type Security

                # Add Owners (managedBy)
                if ($group.OwnersCount -gt 0 -and $group.Owners -ne "") {
                    $owners = $group.Owners -split ";"
                    $validOwners = @()

                    foreach ($owner in $owners) {
                        $ownerRecipient = Get-Recipient -Identity $owner -ErrorAction SilentlyContinue
                        if ($ownerRecipient) {
                            $validOwners += $ownerRecipient.Identity
                        }
                    }

                    if ($validOwners.Count -gt 0) {
                        Set-DistributionGroup -Identity $newGroup.Identity -ManagedBy $validOwners -BypassSecurityGroupManagerCheck
                    }
                }

                # Add Members
                if ($group.MembersCount -gt 0 -and $group.Members -ne "") {
                    $members = $group.Members -split ";"
                    foreach ($member in $members) {
                        $memberRecipient = Get-Recipient -Identity $member -ErrorAction SilentlyContinue
                        if ($memberRecipient) {
                            Add-DistributionGroupMember -Identity $newGroup.Identity -Member $memberRecipient.Identity
                        }
                    }
                } # End New Logic
            }
        }

        # Build with new group id
        #$actualOwners = $group.Owners -split ";" | Where-Object { $_ -ne "" }
        #$actualMembers = $group.Members -split ";" | Where-Object { $_ -ne "" }

        $newGroupsData += New-Object PSObject -Property @{
            MembersCount  = $group.MembersCount
            GroupGUID     = $newGroup.ObjectId
            Owners        = ($group.Owners -split ";" -join ";")
            GroupName     = $groupNameWithPrefix
            GroupType     = $newGroup.GroupType
            Members       = ($group.Members -split ";" -join ";")
            OwnersCount   = $group.OwnersCount
            Status        = "Created"
        }

    } 
    else 
    {
        Write-Host "Group '$($groupNameWithPrefix)' already exists. Skipping creation."

        switch ($group.GroupType) {
            'Security Group' {
                # == Azure AD Group ==
                # Add Owners
                if ($group.OwnersCount -gt 0 -and $group.Owners -ne "") {
                    $owners = $group.Owners -split ";"
                    $existingOwners = Get-AzureADGroupOwner -ObjectId $existingGroupAAD.ObjectId

                    foreach ($owner in $owners) {
                        $ownerUser = Get-AzureADUser -Filter "UserPrincipalName eq '$owner'"
                        if ($ownerUser) {
                            $isAlreadyOwner = $existingOwners | Where-Object { $_.ObjectId -eq $ownerUser.ObjectId }
                            if (-not $isAlreadyOwner) {
                                Add-AzureADGroupOwner -ObjectId $existingGroupAAD.ObjectId -RefObjectId $ownerUser.ObjectId
                            }
                        }
                    }
                }

                # Add Members
                if ($group.MembersCount -gt 0 -and $group.Members -ne "") {
                    $members = $group.Members -split ";"
                    foreach ($member in $members) {
                        $memberUser = Get-AzureADUser -Filter "UserPrincipalName eq '$member'"
                        if ($memberUser) {
                            $isAlreadyMember = Get-AzureADGroupMember -ObjectId $existingGroupAAD.ObjectId | Where-Object { $_.ObjectId -eq $memberUser.ObjectId }
                            if (-not $isAlreadyMember) {
                                Add-AzureADGroupMember -ObjectId $existingGroupAAD.ObjectId -RefObjectId $memberUser.ObjectId
                            }
                        }
                    }
                }
            }
            'Mail-enabled Security Group' {
                # == Exchange Online Group ==
                # Add Owners
                if ($group.OwnersCount -gt 0 -and $group.Owners -ne "") {
                    $owners = $group.Owners -split ";"
                    $validOwners = @()
                    $existingManagedBy = (Get-DistributionGroup -Identity $existingGroupMailEnabled.Identity).ManagedBy

                    foreach ($owner in $owners) {
                        $ownerRecipient = Get-Recipient -Identity $owner -ErrorAction SilentlyContinue
                        if ($ownerRecipient -and ($existingManagedBy -notcontains $ownerRecipient.DistinguishedName)) {
                            $validOwners += $ownerRecipient.Identity
                        }
                    }

                    if ($validOwners.Count -gt 0) {
                        Set-DistributionGroup -Identity $existingGroupMailEnabled.Identity -ManagedBy $validOwners -BypassSecurityGroupManagerCheck
                    }
                }

                # Add Members
                if ($group.MembersCount -gt 0 -and $group.Members -ne "") {
                    $existingMembers = Get-DistributionGroupMember -Identity $existingGroupMailEnabled.Identity
                    $members = $group.Members -split ";"

                    foreach ($member in $members) {
                        $memberRecipient = Get-Recipient -Identity $member -ErrorAction SilentlyContinue
                        if ($memberRecipient -and ($existingMembers | Where-Object { $_.PrimarySmtpAddress -eq $memberRecipient.PrimarySmtpAddress }) -eq $null) {
                            Add-DistributionGroupMember -Identity $existingGroupMailEnabled.Identity -Member $memberRecipient.Identity
                        }
                    }
                }
            }
        }

        $newGroupsData += New-Object PSObject -Property @{
            MembersCount  = $group.MembersCount
            GroupGUID     = if ($existingGroupAAD) { $existingGroupAAD.ObjectId } else { $existingGroupMailEnabled.Guid }
            Owners        = ($group.Owners -split ";" -join ";")
            GroupName     = $groupNameWithPrefix
            GroupType     = $group.GroupType
            Members       = ($group.Members -split ";" -join ";")
            OwnersCount   = $group.OwnersCount
            Status        = "Updated"
        }

    }
}
 
if ($newGroupsData.Count -gt 0) 
{
    $newGroupsData | Export-Csv -Path $newGroupsCsvPath -NoTypeInformation
}

# Disconnect from Azure AD
Disconnect-AzureAD
# Disconnect Exchange
Disconnect-ExchangeOnline -Confirm:$false