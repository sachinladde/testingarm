
Configuration ServerConfiguration {

    Import-DscResource -ModuleName PsDesiredStateConfiguration

    Node 'localhost' {
        WindowsFeature FS-fileserver {
            Ensure = "Present"
            Name   = "FS-fileserver"
        }
        
        WindowsFeature Web-Common-Http {
            Ensure = "Present"
            Name   = "Web-Common-Http"
        }
        
        WindowsFeature Web-Default-Doc {
            Ensure = "Present"
            Name   = "Web-Default-Doc"
        }
        
        WindowsFeature Web-Dir-Browsing {
            Ensure = "Present"
            Name   = "Web-Dir-Browsing"
        }
        
        WindowsFeature Web-Http-Errors {
            Ensure = "Present"
            Name   = "Web-Http-Errors"
        }
        
        WindowsFeature Web-Static-Content {
            Ensure = "Present"
            Name   = "Web-Static-Content"
        }
        
        WindowsFeature Web-Http-Redirect {
            Ensure = "Present"
            Name   = "Web-Http-Redirect"
        }
        
        WindowsFeature Web-DAV-Publishing {
            Ensure = "Present"
            Name   = "Web-DAV-Publishing"
        }

        WindowsFeature Web-Mgmt-Console {
            Ensure = "Present"
            Name   = "Web-Mgmt-Console"
        }

        WindowsFeature Web-Scripting-Tools {
            Ensure = "Present"
            Name   = "Web-Scripting-Tools"
        }

        WindowsFeature Web-Mgmt-Service {
            Ensure = "Present"
            Name   = "Web-Mgmt-Service"
        }

        WindowsFeature Web-Health {
            Ensure = "Present"
            Name   = "Web-Health"
        }

        WindowsFeature Web-Http-Logging {
            Ensure = "Present"
            Name   = "Web-Http-Logging"
        }

        WindowsFeature Web-Log-Libraries {
            Ensure = "Present"
            Name   = "Web-Log-Libraries"
        }

        WindowsFeature Web-ODBC-Logging {
            Ensure = "Present"
            Name   = "Web-ODBC-Logging"
        }

        WindowsFeature Web-Request-Monitor {
            Ensure = "Present"
            Name   = "Web-Request-Monitor"
        }
        WindowsFeature Web-Http-Tracing {
            Ensure = "Present"
            Name   = "Web-Http-Tracing"
        }

        WindowsFeature Web-Performance {
            Ensure = "Present"
            Name   = "Web-Performance"
        }

        WindowsFeature Web-Stat-Compression {
            Ensure = "Present"
            Name   = "Web-Stat-Compression"
        }

        WindowsFeature Web-Dyn-Compression {
            Ensure = "Present"
            Name   = "Web-Dyn-Compression"
        }
        WindowsFeature Web-Security {
            Ensure = "Present"
            Name   = "Web-Security"
        }
        WindowsFeature Web-Filtering {
            Ensure = "Present"
            Name   = "Web-Filtering"
        }
        WindowsFeature Web-IP-Security {
            Ensure = "Present"
            Name   = "Web-IP-Security"
        }
        WindowsFeature Web-Url-Auth {
            Ensure = "Present"
            Name   = "Web-Url-Auth"
        }
        WindowsFeature Web-App-Dev {
            Ensure = "Present"
            Name   = "Web-App-Dev"
        }
        WindowsFeature Web-Net-Ext {
            Ensure = "Present"
            Name   = "Web-Net-Ext"
        }
        WindowsFeature Web-Net-Ext45 {
            Ensure = "Present"
            Name   = "Web-Net-Ext45"
        }
        WindowsFeature Web-AppInit {
            Ensure = "Present"
            Name   = "Web-AppInit"   
        }
        WindowsFeature Web-Asp-Net45 {
            Ensure = "Present"
            Name   = "Web-Asp-Net45"
        }
        WindowsFeature Web-ISAPI-Ext {
            Ensure = "Present"
            Name   = "Web-ISAPI-Ext"
        }
        WindowsFeature Web-ISAPI-Filter {
            Ensure = "Present"
            Name   = "Web-ISAPI-Filter" 
        }
        WindowsFeature NET-Framework-Features {
            Ensure = "Present"
            Name   = "NET-Framework-Features"
        }
        WindowsFeature NET-HTTP-Activation {
            Ensure = "Present"
            Name   = "NET-HTTP-Activation"
        }
        WindowsFeature NET-Non-HTTP-Activ {
            Ensure = "Present"
            Name   = "NET-Non-HTTP-Activ"
        }

        WindowsFeature NET-Framework-45-Features {
            Ensure = "Present"
            Name   = "NET-Framework-45-Features"
        }
        WindowsFeature NET-Framework-45-Core {
            Ensure = "Present"
            Name   = "NET-Framework-45-Core"
        }
        WindowsFeature NET-Framework-45-ASPNET {
            Ensure = "Present"
            Name   = "NET-Framework-45-ASPNET"
        }
        WindowsFeature NET-WCF-Services45 {
            Ensure = "Present"
            Name   = "NET-WCF-Services45"
        }
        WindowsFeature NET-WCF-HTTP-Activation45 {
            Ensure = "Present"
            Name   = "NET-WCF-HTTP-Activation45"
        }
        WindowsFeature NET-WCF-MSMQ-Activation45 {
            Ensure = "Present"
            Name   = "NET-WCF-MSMQ-Activation45"
        }
        WindowsFeature NET-WCF-Pipe-Activation45 {
            Ensure = "Present"
            Name   = "NET-WCF-Pipe-Activation45"
        }
        WindowsFeature NET-WCF-TCP-Activation45 {
            Ensure = "Present"
            Name   = "NET-WCF-TCP-Activation45"
        }

        WindowsFeature BitLocker {
            Ensure = "Present"
            Name   = "BitLocker"
        }
        WindowsFeature EnhancedStorage {
            Ensure = "Present"
            Name   = "EnhancedStorage"
        }
        WindowsFeature MSMQ {
            Ensure = "Present"
            Name   = "MSMQ"
        }
        WindowsFeature MSMQ-Services {
            Ensure = "Present"
            Name   = "MSMQ-Services"
        }
        WindowsFeature MSMQ-Server {
            Ensure = "Present"
            Name   = "MSMQ-Server" 
        }
        WindowsFeature SNMP-Service {
            Ensure = "Present"
            Name   = "SNMP-Service"
        }
        WindowsFeature Windows-Identity-Foundation {
            Ensure = "Present"
            Name   = "Windows-Identity-Foundation"
        }
        WindowsFeature Windows-Internal-Database {
            Ensure = "Present"
            Name   = "Windows-Internal-Database"
        }
        WindowsFeature Windows-Server-Backup {
            Ensure = "Present"
            Name   = "Windows-Server-Backup"
            IncludeAllSubFeature  = $true
        }
        WindowsFeature WAS 
        {
            Ensure = "Present"
            Name   = "WAS"
            IncludeAllSubFeature  = $true
        }
        
        Registry SSL {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
            ValueName = "Functions"
            ValueData = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384,TLS_ECDHE_ECD"
            ValueType = "String"
        }
    }
}

Configuration WebServerConfiguration {

    param
    (
        [parameter(Mandatory)]
        [String]
        $ValidationKey,

        [parameter()]
        [String]
        $Validation = "HMACSHA256",

        [parameter(Mandatory)]
        [String]
        $DecryptionKey,
        
        [parameter()]
        [String]
        $Decryption = "AES",

        [parameter()]
        [Hashtable]
        $MachineConfigs = @{ 
            "11x86" = "C:\WINDOWS\Microsoft.NET\Framework\v1.1.4322\CONFIG\machine.config"
            "20x86" = "C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\CONFIG\machine.config"
            "40x86" = "C:\WINDOWS\Microsoft.NET\Framework\v4.0.30319\CONFIG\machine.config"
            "20x64" = "C:\WINDOWS\Microsoft.NET\Framework64\v2.0.50727\CONFIG\machine.config"
            "40x64" = "C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\CONFIG\machine.config"
        }
    )

    Import-DscResource -ModuleName PsDesiredStateConfiguration

    # This config is an extension of the base ServerConfiguration
    ServerConfiguration ServerConfiguration {}

    Node 'localhost' {
        Script MachineKey {
            GetScript  = {
                Write-Verbose "Configs to check"
                $machineConfigsLocal = $using:MachineConfigs
                $debugConfig = $machineConfigsLocal | Out-String
                Write-Verbose $debugConfig 
                $result = ""
                foreach ($version in $machineConfigsLocal.Keys) {
                    if (Test-Path $machineConfigsLocal[$version]) { 
                        $xml = [xml](get-content $machineConfigsLocal[$version])
                        $root = $xml.get_DocumentElement()
                        $system_web = $root."system.web"
                        if ($system_web.machineKey -eq $nul) { 
                            Write-Verbose "machineKey is null for $version" 
                            $result = "$($result)NULL,"
                        }
                        else {
                            $result = "$($result)$($system_web.SelectSingleNode("machineKey").GetAttribute("validationKey")),"
                            Write-Verbose "Validation Key: $($system_web.SelectSingleNode("machineKey").GetAttribute("validationKey"))" 
                            Write-Verbose "Decryption Key: $($system_web.SelectSingleNode("machineKey").GetAttribute("decryptionKey"))" 
                            Write-Verbose "Decryption: $($system_web.SelectSingleNode("machineKey").GetAttribute("decryption"))" 
                            Write-Verbose "Validation: $($system_web.SelectSingleNode("machineKey").GetAttribute("validation"))" 
                        }
                    }
                   else { 
                        Write-Verbose "$version is not installed on this machine" 
                        $result = "$($result)NA,"
                    } 
                }
                $result = $result.Trim(",")
                Write-Verbose $result
                return @{ 'Result' = "$result" }
            }
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $values = [scriptblock]::Create($GetScript).Invoke()
                $valuesString = $values | Out-String
                Write-Verbose "Return value from Get-Script: $($valuesString)"
                Write-Verbose "Validation Keys: $($values.Result)"
                $foundKeys = $values.Result.split(",");
                foreach ($foundKey in $foundKeys) {
                    if (($foundKey -ne "NA") -and ($foundKey -ne $using:ValidationKey)) {
                        Write-Verbose -Message ('Found key {0}' -f $foundKey)        
                        return $false;
                    }
                }
                return $true
            }
            SetScript  = {
                $machineConfigsLocal = $using:MachineConfigs
                foreach ($version in $machineConfigsLocal.Keys) {
                    if (Test-Path $machineConfigsLocal[$version]) {
                        $xml = [xml](get-content $machineConfigsLocal[$version])
                        $currentDate = (get-date).tostring("mm_dd_yyyy-hh_mm_s")
                        $xml.Save($machineConfigsLocal[$version] + "_$currentDate")
                        $root = $xml.get_DocumentElement()
                        $system_web = $root."system.web"
                        if ($system_web.machineKey -eq $nul) { 
                            $machineKey = $xml.CreateElement("machineKey") 
                            $system_web.AppendChild($machineKey)
                        }
                        $system_web.SelectSingleNode("machineKey").SetAttribute("validationKey", "$using:ValidationKey")
                        $system_web.SelectSingleNode("machineKey").SetAttribute("decryptionKey", "$using:DecryptionKey")
                        $system_web.SelectSingleNode("machineKey").SetAttribute("decryption", "$using:Decryption")
                        $system_web.SelectSingleNode("machineKey").SetAttribute("validation", "$using:Validation")
                        $xml.Save($machineConfigsLocal[$version])
                    }
                    else { 
                        Write-Verbose "$version is not installed on this machine" 
                    }
                }
            }
        }
    }
}

Configuration ConfigServiceServerConfiguration {  
    param
    (
        [parameter(Mandatory)]
        [String]
        $NETcoreversion
    )
    Import-DscResource -ModuleName PsDesiredStateConfiguration

    # This config is an extension of the base ServerConfiguration
    ServerConfiguration ServerConfiguration {}

    Node 'localhost' {
        Script NETcore {
            GetScript  = {
                               $inputmajorv = $NETcoreversion.Split('.')
                               $sdk = (dir (Get-Command dotnet).Path.Replace('dotnet.exe', 'sdk')).Name
                               $majorversion = $sdk.Split('.')               
                               #checking for .net core sdk to be present or not 
                               if($sdk -eq $null -or $majorversion[0] -ne $inputmajorv[0] -or $majorversion[1] -ne $inputmajorv[1] )
                               {
                               Write-Verbose "$version is not installed on this machine" 
                               }
                               return @{ 'Result' = "$sdk" }
                           }
               
               TestScript = {
                               #checking for required SDK versions
                               $versions = [scriptblock]::Create($GetScript).Invoke()
                               $inputmajorv = $NETcoreversion.Split('.')
                               $sdkk = $versions['Result']
                               if($sdkk -ne $null){
                               $majorversion = $sdkk.Split('.')
                               if($majorversion[0] -eq $inputmajorv[0] -and $majorversion[1] -eq $inputmajorv[1])
                               {
                                   return $true;
                               }
                               }
                               return $false;      
                           }

            SetScript  =    {
                            Write-Output "Installing .NET version - $($NETcoreversion)" 
                            Invoke-WebRequest 'https://dot.net/v1/dotnet-install.ps1' -OutFile 'dotnet-install.ps1';
                            ./dotnet-install.ps1 -InstallDir '~/.dotnet' -Version $NETcoreversion;
                }
            }
        }
    }

    
Configuration ADDC
{   
    param
    (
        [parameter(Mandatory)]
        [String]
        $PrimaryDNSserverIP,

        [parameter(Mandatory)]
        [String]
        $secondaryDNSIP,

        [parameter(Mandatory)]
        [String]
        $staticIPaddress,
        
        [parameter(Mandatory)]
        [String]
        $subnetmask,

        [parameter(Mandatory)]
        [String]
        $defaultgatewayIP,

        [parameter(Mandatory)]
        [String]
        $domainName,

        [parameter(Mandatory)]
        [String]$secdomainpasswd, 

        [parameter(Mandatory)]
        [String]
        $DCReplicationSource, 

        [parameter(Mandatory)]
        [String]
        $domainadminusername, 
        
        [parameter(Mandatory)]
        [String]
        $siteName
    )
    Import-DscResource -ModuleName PsDesiredStateConfiguration 
    node localhost    
    {
        WindowsFeature DNS 
        { 
            Ensure = "Present" 
            Name = "DNS"
            IncludeAllSubFeature = $true
           
        }

        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services"
            IncludeAllSubFeature = $true
           
        }
        
        Script NetworkAdapter
        {
        GetScript = {
        Return @{
            Result = [string](get-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter| Where-Object Name -Like "Ethernet*"|Select-Object -First 1).Name -AddressFamily IPv4).ServerAddresses
        }
        }
        TestScript = {
            $ipaddress = [scriptblock]::Create($GetScript).Invoke()
            $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "up"}
            $interface = $adapter | Get-NetIPInterface -AddressFamily IPv4
            
            if ( $ipaddress['Result'] -eq $PrimaryDNSIpaddress -and $interface.Dhcp -eq "Disabled") 
            {
            Write-Verbose "DNS server and static IP set"
            Return $true
            } 
            Write-Verbose "Static IP and DNS Server not set"
            Return $false
        }   
        SetScript = {

            #starting to set private IP address of the adapter
            $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "up"}
            # Removing any existing IP, gateway from our ipv4 adapter
            If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
            $adapter | Remove-NetIPAddress -AddressFamily 'IPv4' -Confirm:$false
            }
            If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
            $adapter | Remove-NetRoute -AddressFamily 'IPv4' -Confirm:$false
            }
            # Configure the IP address and default gateway
            $adapter | New-NetIPAddress `
             -AddressFamily 'IPv4' `
             -IPAddress $staticIPaddress `
             -PrefixLength $subnetmask `
             -DefaultGateway $defaultgatewayIP
            # Configure the DNS client server IP addresses
            $adapter | Set-DnsClientServerAddress -ServerAddresses $PrimaryDNSserverIP, $secondaryDNSIP, 127.0.0.1 ;
            }
        }

        Script DCpromotion
        {
        GetScript = {
            $DomainRole = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole
            return @{ 'Result' = "$DomainRole" }
        }
        TestScript = {
            $result = [scriptblock]::Create($GetScript).Invoke()
            
            if ( $result['Result'] -match '4|5' ) 
            {
            Write-Verbose "This is already a Domain Controller"
            Return $true
            } 
            Write-Verbose "This is not a DC server"
            Return $false
        }   
        SetScript = {
            Import-Module ADDSDeployment -Force          
            $domainadmin = $domainadminusername + "@" + $domainName
            $mydomaincreds = New-Object System.Management.Automation.PSCredential($domainadmin, $secdomainpasswd)
            Install-ADDSDomainController `
            -NoGlobalCatalog:$false `
            -CreateDnsDelegation:$false `
            -Credential $mydomaincreds `
            -CriticalReplicationOnly:$false `
            -DatabasePath "C:\windows\NTDS" `
            -DomainName $domainName `
            -InstallDns:$true `
            -LogPath "C:\windows\NTDS" `
            -NoRebootOnCompletion:$false `
            -ReplicationSourceDC $DCReplicationSource `
            -SiteName $siteName `
            -SysvolPath "C:\windows\SYSVOL" `
            -Force:$true -SafeModeAdministratorPassword $secdomainpasswd
        }
        #DependsOn = '[WindowsFeature]ADDSInstall'      
    }
}
}

