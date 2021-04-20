Param (
    [Parameter(Mandatory = $true)]
    [String] $SourceKeyVault,
    [Parameter(Mandatory = $true)]
    [String] $DestinationKeyVault,
    [Parameter(Mandatory = $true)]
    [String] $Subscription
)

$connectionName = "AzureRunAsConnection"
try {

    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection = Get-AutomationConnection -Name $connectionName 

    "Logging in to Azure..."
    Add-AzAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
}
catch {
    if (!$servicePrincipalConnection) {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    }
    else {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}
   
Set-AzContext -SubscriptionId $Subscription
      
Get-AzADServicePrincipal -ApplicationId $servicePrincipalConnection.ApplicationId

$SPObj = Get-AzADServicePrincipal -ApplicationId $servicePrincipalConnection.ApplicationId
    
Set-AzKeyVaultAccessPolicy -VaultName $DestinationKeyVault -ObjectId $SPObj.Id -PermissionsToKeys backup, restore, delete -PermissionsToSecrets backup, restore, delete -PassThru
    

Set-AzKeyVaultAccessPolicy -VaultName $SourceKeyVault -ObjectId $SPObj.Id -PermissionsToKeys list -PermissionsToSecrets list -PassThru

$Keys = Get-AzKeyVaultKey -VaultName $SourceKeyVault | Select-Object Name
$Secrets = Get-AzKeyVaultSecret -VaultName $SourceKeyVault | Select-Object Name
  
foreach ($Key in $Keys) {
    Backup-AzKeyVaultKey -VaultName $SourceKeyVault -Name $Key.Name -OutputFile './BackupKey.blob' 
    Remove-AzKeyVaultKey -VaultName $DestinationKeyVault -Name $Key.Name -Force #-PassThru 
    Restore-AzKeyVaultKey -VaultName $DestinationKeyVault -InputFile "./BackupKey.blob"
}
    
foreach ($Secret in $Secrets) {
    Backup-AzKeyVaultSecret -VaultName $SourceKeyVault -Name $Secret.Name -OutputFile './BackupSecret.blob' 
    Remove-AzKeyVaultSecret -VaultName $DestinationKeyVault -Name $Secret.Name -Force #-PassThru 
    Restore-AzKeyVaultSecret -VaultName $DestinationKeyVault -InputFile "./BackupSecret.blob"
}