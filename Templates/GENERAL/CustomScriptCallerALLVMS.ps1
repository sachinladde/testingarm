$stgaccname = "arvdevstrps001"   # existing storage account name
$containerName = "customscriptextensioncontainer" # name of the container within the Storage account holding scripts
$rgname = "GAV-ARV-DEV-GEN-01" # name of the resource group where storage account is present
$location = "eastus" #location of stg acc and vm (should be the same)

#$filename = "SR_F_diskinit.ps1" # Name of the powershell script that is in the Blob storage

$vmname = "arvdevtest003"  # Name of the VM for which the Custom extension is required
$VMextensionName = "SRF_DiskINit_CustomscriptExt"   # Name of the extension

$SubsID = "b9b4d184-4d3d-48be-bc6d-ea7c80fdc35f"  

Select-AzureRmSubscription -Subscription $SubsID

# Get the Storage Account
$stgacc = Get-AzureRmStorageAccount -ResourceGroupName $rgname -Name $stgaccname 
# Get the container within and set the permission as accessible for Blob
#$stgacc | Get-AzureStorageContainer -Name $containerName | Set-AzureStorageContainerAcl -Permission Blob


$stgaccname = $stgacc.StorageAccountName
$rgname = $stgacc.ResourceGroupName

# Set the Custom Scipt Extension for the VM
#$vms = Get-AzureRmVM -ResourceGroupName $rgname

#foreach($vm in $vms)
#{
$vm = Get-AzureRmVM -ResourceGroupName "GAV-ARV-DEV-GEN-01" -Name "arvdevtest003"
$vmname = $vm.Name

$a = Set-AzureRmVMCustomScriptExtension -ContainerName $containerName -Location $location -FileName ServerRF_diskInit.ps1 -Run ServerRF_diskInit.ps1 `
-StorageAccountName $stgaccname -ResourceGroupName $rgname -VMName $vmname -Name $VMextensionName 
if($a.IsSuccessStatusCode -eq $True)
{
Write-Host "Custom Script Extension "
}
#}