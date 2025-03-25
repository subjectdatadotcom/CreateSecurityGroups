# 🛡️ Security Group Provisioning Script

This PowerShell script automates the provisioning and updating of **Azure AD Security Groups** and **Mail-Enabled Security Groups** in Exchange Online. It is designed to assist with **tenant migrations**, **bulk group creation**, or **user-to-group mapping** from legacy environments using clean and structured CSV input.

---

## 🚀 Features

- ✅ Create Azure AD security groups or mail-enabled groups based on input
- ✅ Add group owners and members from mapped users
- ✅ Skip duplicate members or owners already present
- ✅ Log and export all group creation and update activities
- ✅ Track and export unmapped users for remediation
- ✅ Support for custom prefixes (e.g., `TR -`) for naming consistency
- ✅ Works with AzureAD and ExchangeOnline modules

---

## 📁 Input Files

Place these CSVs in the root script directory:

### `report.csv`
Contains the source group data to be migrated.

| GroupName   | GroupType                | Owners                | Members               | OwnersCount | MembersCount |
|-------------|--------------------------|------------------------|------------------------|--------------|---------------|
| HR Group     | Security Group           | user1@domain.com       | user2@domain.com       | 1            | 1             |
| Sales Team   | Mail-enabled Security Group | manager@domain.com    | emp1@domain.com;emp2@domain.com | 1    | 2             |

### `mappings.csv`
Maps legacy email addresses to current tenant accounts.

| SourceEmail         | TargetEmail              |
|----------------------|--------------------------|
| user1@oldtenant.com  | user1@newtenant.com      |
| user2@oldtenant.com  | user2@newtenant.com      |

---

## 📤 Outputs

- `Reports\To_be_Created_security_groups.csv`: Processed group data post-mapping
- `Reports\created_new_groups.csv`: Final list of created or updated groups with member/owner counts
- `Reports\unmapped_users.csv`: Any users that couldn't be mapped using `mappings.csv`

---

## 🧠 Requirements

- PowerShell 5.1 or newer
- Modules:
  - `AzureAD`
  - `ExchangeOnlineManagement`

Use the following commands to install if needed:

```powershell
Install-Module AzureAD -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser

🔐 Permissions
Ensure you have:

Azure AD Global Admin (or Group Administrator) role

Exchange Online admin permissions

🛠️ How to Run

.\CreateSecurityGroups.ps1

This will:

Connect to Azure AD and Exchange Online

Load and process your input files

Create or update groups

Export reports to the Reports\ folder

