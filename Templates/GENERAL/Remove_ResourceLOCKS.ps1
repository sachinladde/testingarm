# Trust PSGallery repository to install the Az module, avoids prompt in commnad line
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
# Install Az powershell Module
Install-Module -Name Az -AllowClobber -Scope CurrentUser
# Remove locks from every resourceGroup
$removableLockHash =  @{removableLock = true}; 
$resourceGroups = Get-AzResourceGroup -Tag $removableLockHash
Write-Host "Deleting Locks from ResourceGroups with removableLock Tag set to true :" 
foreach($resourceGp in $resourceGroups)
{
    # get the name of resource group
    $locks = Get-AzResourceLock -ResourceGroupName $resourceGp.ResourceGroupName
     #remove locks
    foreach($lock in $locks)
    {
        $lockid = $null 
        $lockid = $lock.LockId
        Remove-AzResourceLock -LockId $lockid -Force
        Write-Host "ResourceGroup Name: $($resourceGp.ResourceGroupName) ,  LockName : $($lock.name)"
        Write-Host "-----------------"
    }
}