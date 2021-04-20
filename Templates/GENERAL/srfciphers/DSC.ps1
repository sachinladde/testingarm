
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