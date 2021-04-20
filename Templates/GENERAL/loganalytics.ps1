$subscriptionId = "63f2f6e3-89a1-4677-a780-2f788788f101"

$vmrg = "GAV-ARV-PRD-GEN-01" 

#$VMname = "arvpjmp001"

$diagnosticsStorageAccountRGName = "GAV-ARV-PRD-GEN-01"

$diagnosticsStorageAccountName = "arvprdstrdag001"

$logAnalyticsName = "gav-arv-prd-mon-la-001"

$logAnalyticsResourceGroupName = "GAV-ARV-PRD-MON-01" 

$retentionInDays = "360"

# Build Storage account scope:
    $diagnosticsStorageAccountId = "/subscriptions/$subscriptionId/resourceGroups/$diagnosticsStorageAccountRGName/providers/Microsoft.Storage/storageAccounts/$diagnosticsStorageAccountName"


# Get Log Analytics Workspace:
    $logAnalyticsWorkspace = Get-AzureRmResource -Name $logAnalyticsName -Verbose `
            -ResourceGroupName $logAnalyticsResourceGroupName -ResourceType "Microsoft.OperationalInsights/workspaces"

# Get Log Analytics Workspace Id:
    $logAnalyticsWorkspaceId = $logAnalyticsWorkspace.Properties.customerId


    Write-Output "Log Analytics Workspace Id to be used: $logAnalyticsWorkspaceId"
    Write-Output "Log Analytics Workspace name to be used: $logAnalyticsName"

#Get *ALL* Virtual Machines in a subscription
#$vm=Get-AzureRmVM -ResourceGroupName $vmrg -Name $VMname
$vms = Get-AzureRmVM -ResourceGroupName $vmrg 
#$vms=appvm
#$vm = Get-AzureRmVM -ResourceGroupName $vmrg -Name $VMname
$vms

$vmcount = 0

foreach($vm in $vms)
    {
        $VMname=$vm.name
        
            Write-Output "*********************************************"
            Write-Output "Virtual Machine Information..."      
            Write-Output ""      
            Write-Output $vm      
            
            #Get the existing settings     
            $diagSetting = Get-AzureRmDiagnosticSetting -ResourceId $vm.Id
   
            Write-Output "**"
            Write-Output "Diag setting metrics count: " $diagSetting.Metrics.Count
            Write-Output "Logs setting metrics count: " $diagSetting.Logs.Count
            Write-Output "**"
   
            Write-Output ""
            Write-Output "Resource Diagnostic Settings..."
            Write-Output ""
            Write-Output $diagSetting
            Write-Output "*********************************************"
        

            Write-Output "Applying Azure Diagnostic settings..." 
# Set logs and metrics setting for resource:
             

 ### Enabling the diagnostics 
           Set-AzureRmDiagnosticSetting -ResourceId $vm.Id -StorageAccountId $diagnosticsStorageAccountId `
          -Enabled $True -RetentionEnabled $True -RetentionInDays $retentionInDays -WorkspaceId $logAnalyticsWorkspace.ResourceId
   

                            #########      ########       #########
#uncomment if we want to also 'Connect' the VMs with the mentioned WORKSPACE by setting an "Extension" of "Microsoft Monitoring Agent" for the VMs
                            #########      ########       #########
  
  # installing OMS monitoring extensions on VMs using the workspace ID and the workspace key 



  Write-Output "Installing OMS monitoring extensions on VMs using the workspace ID and the workspace key"

  $OMSWorkspaceKey = Get-AzureRmOperationalInsightsWorkspaceSharedKeys `
                         -ResourceGroupName $logAnalyticsWorkspace.ResourceGroupName `
                         -Name $logAnalyticsWorkspace.Name


$OMSpublicsettings=@{ "workspaceId" = $logAnalyticsWorkspaceId }

 $OMSprotectedsettings=@{ "workspaceKey" = $OMSWorkspaceKey.primarysharedkey }        

  Set-AzureRmVMExtension -ResourceGroupName $vm.ResourceGroupName `
  -ExtensionName "MicrosoftMonitoringAgent" `
  -VMName $VMname `
  -Location $vm.Location `
  -Publisher "Microsoft.EnterpriseCloud.Monitoring" `
  -ExtensionType "MicrosoftMonitoringAgent" `
  -TypeHandlerVersion 1.0 `
  -Settings $OMSpublicsettings `
  -ProtectedSettings $OMSprotectedsettings `
  -ForceRerun true
  
  
   Write-Output "VM Extension modified "
  

        $vmcount += 1
  }
    Write-Host "Azure Virtual Machines modified: $vmcount" -ForegroundColor Green -BackgroundColor Black
 
