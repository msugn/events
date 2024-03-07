
$username ='msugFTW:)'
$securePassword = Read-Host -Prompt 'Enter your password' -AsSecureString
$clearTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePassword

######## Recon auth possiblities 1b730954-1685-4b74-9bfd-dac224a7b894 ################ 
Invoke-GraphAPIAuth -Username $username -Password $clearTextPassword 
Import-Module MSOline -EA 0
Connect-MsolService -Credential $credential
Get-MSolGroup -All

##################### Using AADInternal module  ######################
Import-Module AADInternals

Get-AADIntAccessTokenForMSGraph -Credentials $credential -SaveToCache
Get-AADIntGlobalAdmins
Get-AADIntTenantDetails
Get-AADIntTenantAuthPolicy 
Get-AADIntConditionalAccessPolicies


#### Lockdown approle assigment and create app if not exists ####

Import-Module Microsoft.Graph.Applications
Connect-MgGraph -Scopes Application.ReadWrite.All -UseDeviceCode

$AppIds = @("14d82eec-204b-4c2f-b7e8-296a70dab67e")

foreach ($AppId in $AppIds) {
    # Get existing service principle
    $SP = (Get-MgServicePrincipal -Filter "AppId eq '$($AppId)'")
    # Create service principal if not exists
    if (-not $SP) { 
        $SP = New-MGServicePrincipal -AppId $AppId 
        Write-Host "  ┖─ Did not found service principal with AppId $AppId so created one" -ForegroundColor Yellow
    } else {
        Write-Host "  ┖─ Found service principal with AppId $AppId" -ForegroundColor Green
    }
    # Set assignment required
    Update-MgServicePrincipal -ServicePrincipalId $SP.Id -AppRoleAssignmentRequired:$true
    Write-Host "  ┖─ Updated assignment required for $AppId with display name $($SP.DisplayName)" -ForegroundColor Green
}

#block MSOL this will trigger an admin consent flow: 
Connect-MGGraph -Scopes 'Policy.ReadWrite.Authorization'
Update-MgPolicyAuthorizationPolicy -BlockMsolPowerShell:$true



#Get sign-in specific apps from audit log
Connect-MgGraph -Scopes 'AuditLog.Read.All' -UseDeviceCode
[array]$AuditRecords = Get-MgAuditLogSignIn  -Sort "createdDateTime DESC" -Filter "AppId eq '1950a258-227b-4e31-a9cf-717495945fc2'"
#total brukere
$AuditRecords | Group-Object UserPrincipalName -NoElement | Sort-Object Count -Descending| Select-Object Name, Count
## with CA Status
$AuditRecords | Group-Object UserPrincipalName, ConditionalAccessStatus -NoElement | Sort-Object Count -Descending | Select-Object Name, @{Name='ConditionalAccessStatus'; Expression={($_.Group | Select-Object -Expand ConditionalAccessStatus | Sort-Object -Unique) -join ', '}}, Count
