# get all resources in a RG

$rgname = ""


$resources = Get-AzureRmResource -ResourceGroupName GAV-ARV-DR-BKP-01

foreach($resource in $resources)
{

$groupname = $resource.ResourceGroupName
$resourcetype = $resource.ResourceType
$resourcename = $resource.Name

New-AzureRmResourceLock -LockLevel CanNotDelete -ResourceName $resourcename -LockName "Lock-AccidentalDeletion" `
-ResourceType $resourcetype -ResourceGroupName $groupname -Force
}


# get all locks in the subscription

$all_locks = Get-AzureRmResourceLock 
$all_locks | Out-File -FilePath "C:\Users\nilansh.netan\Desktop\abcd.xlsx"

foreach ($lock in $all_locks)  #empty variable $lock to store one by one value in array of $all_Locks  
{

            #writing info Column Wise ####The left siders are column names
            $ResourcesInfo = [pscustomobject]@{
                'Resource Name'= $lock.ResourceName
                'Resource Type'= $lock.ResourceType
                'Lock Name'= $lock.Name
                'ResourceGroupName' = $lock.ResourceGroupName
                 }

            $objs += $ResourcesInfo ##### creating $objs variable which stores(adds rows) values from the upper table each time loop runs  

        }  
    
#$objs | Export-Csv -NoTypeInformation -Path C:\Users\nilansh.netan\Desktop\file.csv


