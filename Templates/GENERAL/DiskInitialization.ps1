param([char[]]$DriveLetters, [string[]]$DriveLabels)
# get all the disks 
$disks = @()
$disks = @(Get-Disk | Where-Object partitionstyle -eq 'raw' | Sort-Object size)

Write-Host "Found $($disks.Count) raw disks to init"

$count = 0
if((($DriveLetters.Count -ne $disks.Count) -or ($DriveLabels.Count -ne $disks.Count)) -and ($disks.Count -ne 0)) {
    throw "Incorrect number of DriveLetters or DriveLabels for raw disks"
}

# for every disk in an array of disks
foreach ($disk in $disks) 
{
        # use GPT technique as partion style to support large disk sizes as well
        $disk | Initialize-Disk -PartitionStyle GPT -PassThru |
        New-Partition -UseMaximumSize -DriveLetter $DriveLetters[$count] |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel $DriveLabels[$count] -Confirm:$false -Force
        $count++
}