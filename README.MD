# AirVault IaC

This repo should contain all templates and scripts to deploy and provision the infrastructure used to host AirVault.

The deployment is managed using an Azure DevOps release pipeline. 


## Pre-Deployment Requirements

The following list of dependencies need to be met before a deployment can be successful:
- Create a keyvault resource that contains the following data:
  - Key: Key used for disk encryption. The key should be created using the Templates/KEYVAULT/Keygen.ps1 script. The url for the key should then be used to populate the keyEncryptionKeyURL parameter. 
  - Secret: A password used by all VMs. The url for the password will then be used to populate the virtualMachineAdminPassword parameter.  
  - Secret: The sslCertificateData for the Application Gateway (appGatewayCertData). The url for the appGatewayCertData will then be used to populate the sslCertificateData parameter.
  - Secret: validateKey is a length 64 key used to set the machineKey config for all web server VMs
  - Secret: decryptionKey is a length 24 key used to set the machineKey config for all web server VMs


## Post-Deployment Requirements


