## Windows Post-Exp
> ___

Aqui deixei algumas tecnicas de pós-exploração em ambiantes Windows que achei mais relevantes para o contexto do mundo real (In the wild). Resolvi tirar notas dessas tecnicas enquanto lia o livro The Hacker Playbook 3 (https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing/dp/1980901759


## Pegando Cleartext Creds da memória
> ___

#### Forçando o WDigest a armazenar credenciais em plaintext

Como parte do WDigest authentication provider, as versões do Windows até 8 e 2012 costumavam armazenar credenciais de logon na memória em plaintext por padrão, o que não é mais o caso com versões mais recentes do Windows. 

Mas ainda é possível forçar o WDigest a armazenar os secrets em plaintext.


Então como fazer isso? A opção mais fácil é definir a resgistry key para colocar o senhas de volta no LSASS. Dentro do HKLM existe uma config  ```UseLogonCredential``` que, se definido como 0, armazenará as credenciais de volta na memória:

- ```reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 ```

- Pelo Empire pode ser assim:
```shell reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDige /v UseLogonCredential /t REG_DWORD /d 1 f```


O problema com esta configuração é que precisaremos que o usuário faça login novamente no sistema. Você pode forçar lock-screen, reboot ou logoff, para poder capturar credenciais em clear text. A maneira mais fácil é bloquear sua estação de trabalho:

- ```rundll32.exe user32.dll,LockWorkStation```

Depois de ativar a tela de bloqueio e fazer com que o alvo façam login novamente, podemos executar o Mimikatz e recuperar as senhas.


REFS: 
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/forcing-wdigest-to-store-credentials-in-plaintext
- https://github.com/gentilkiwi/mimikatz/wiki


#### E se não conseguirmos acessar uma conta local admin? 

Uma alternativa é examinar a memória do usuário para ver se existe credenciais armazenadas em plaintext. 


Para isso tem um tool chamada Mimikittenz (https://github.com/putterpanda/mimikittenz). O que Mimikittenz faz é utilizar a função ReadProcessMemory() do Windows para extrair senhas em plaintext de vários processos, como de navegadores.

#### Pegando senhas do Windows Credential Store e navegadores.

O Windows Credential Store é um recurso padrão do Windows que salva nomes de usuário, senhas e certificados para sistemas, sites e servidores.

- Web Creds: https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1

- Windows Credentials: https://github.com/peewpw/Invoke-WCMDump/blob/master/Invoke-WCMDump.ps1

- Para creds do Chrome use o modulo do Empire powershell/collection/ChromeDump: https://www.infosecmatter.com/empire-module-library/?mod=powershell/collection/ChromeDump

- histórico e cookies do navegador: https://github.com/sekirkity/BrowserGather 

- A tool SessionGopher (https://github.com/fireeye/SessionGopher) pode pegar hostnames e senhas salvas do WinSCP, PuTTY, SuperPuTTY, FileZilla, e Microsoft Remote Desktop. (https://www.infosecmatter.com/empire-module-library/?mod=powershell/credentials/sessiongopher )


## Living Off of the Land Windows Domain?????
> ___

#### Service Principal Names (SPNs)

Service Principal Names, ou SPN, é um recurso do Windows que permite que um client identifique exclusivamente a instância de um service. SPNs são usados pela autenticação Kerberos para associar uma instância de serviçe a uma conta de service.

( https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx ).

- lista contas com o SPN setado:
```setspn -T [DOMAIN] -F -Q /```

> -T = query do domain
> -F = queries do AD forest, em vez de domain level
> -Q = roda em cada domain ou forest
>  / = todas contas

#### Infos mais detalhadas dos users no AD

Modulos PowerView do Empire:
- situational_awareness/network/powerview/get_user
- situational_awareness/network/powerview/get_group_member
- situational_awareness/network/powerview/get_computer
- https://enigma0x3.net/2016/01/28/an-empire-case-study/
- https://www.infosecmatter.com/empire-module-library/

#### Lateral Moviment - Migrating Processes (ReflectivePick)

Executa codigo Powershell me qualquer processo...

PSInject do Empire: "has the ability to inject an agent into another process using
ReflectivePick to load up the .NET common language runtime into a process and
execute a particular PowerShell command, all without starting a new
powershell.exe process!”

- https://bc-security.org/empire-4-4/

#### Lateral Movement via DCOM

Existem alguns recursos interessantes do Windows que podemos aproveitar usando o Distributed Component Object Model (DCOM). DCOM  é um recurso do Windows para comunicação entre softwares em diferentes computadores remotos.

- https://www.ired.team/offensive-security/lateral-movement/t1175-distributed-component-object-model
- https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
- https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/
- https://www.cybereason.com/blog/dcom-lateral-movement-techniques

#### Pass-the-Hash

O uso mais básico do PTH é atacar o local admin. Atualmente isso é raro de encontrar porque, por padrão, a conta de local admin está desabilitada e recursos de segurança mais recentes surgiram, como o Local Administrator Password Solution (LAPS), que cria senhas aleatórias para cada estação de trabalho. No passado, obter o hash da conta de local admin em uma estação de trabalho era idêntico em toda a organização, o que significava que um comprometimento destruía toda a empresa. Obviamente, os requisitos para isso são que você seja um local admin, que a conta de local admin "administrador" esteja habilitada e que seja a conta RID 500 (o que significa que deve ser a conta de administrador original e não pode ser uma conta de administrador local recém-criada).

- https://book.hacktricks.xyz/windows-hardening/ntlm#pass-the-hash
- https://www.ired.team/offensive-security/privilege-escalation/pass-the-hash-privilege-escalation-with-invoke-wmiexec
- https://www.thehacker.recipes/ad/movement/ntlm/pth

Os exemplos acima são a maneira antiga de lateral moviment e é um achado raro. Se você ainda está tentando abusar de contas de a local admin, mas está em um ambiente que possui LAPS, você pode usar algumas ferramentas diferentes para retirá-las do AD. Isso pressupõe que você já tenha um domain admin privilegiado ou uma conta do tipo helpdesk:

```ldapsearch -x -h 10.100.100.200 -D "elon.muskkat" -w password -b "dc=cyberspacekittens,dc=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd```


> -x basic authentication
>
> -h 192.168.80.10 - conecta ao Domain Controller
>
> -D "helpdesk" -w ASDqwe123 - Login como helpdesk, com o pass ASDqwe123
>
> -b "dc=sittingduck,dc=info" - base LDAP object.
>
> "(ms-MCS-AdmPwd=*)" - Filtra os objects que nao são ms-MCS-AdmPwd. (se você tiver permissão)
>
> ms-MCS-AdmPwd - mostra só o object ms-MCS-AdmPwd


- https://room362.com/post/2017/dump-laps-passwords-with-ldapsearch/


#### Creds das Service Accounts (Kerberoasting)

E se você se encontrar em um cenário em que você é um usuário limitado, não consegue extrair senhas da memória e não teve sorte com as senhas no sistema host...

O que é Kerberoast?
- it allows any domain user to request kerberos tickets from TGS that are encrypted with NTLM hash of the plaintext password of a domain user account that is used as a service account and crack them offline avoiding AD account lockouts.

permite que qualquer usuário de domínio solicite tickets TGS ao Kerberos que são criptografados com hash NTLM da senha plaintext de uma conta de usuário de domínio usada como conta de service e quebre-os offline, evitando bloqueios de conta do AD.

- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
- https://www.thehacker.recipes/ad/movement/kerberos/kerberoast


## Dump dos hash do Domain Controller (Shadow Copy ou Raw Copy)

Once we have obtained Domain Administrative access, the old way to pull all
the hashes from the DC was to run commands on the domain controller and use
Shadow Volume or Raw copy techniques to pull off the Ntds.dit file.
Since we do have access to the file system and can run commands on the domain
controller, as an attacker, we want to grab all the Domain hashes stored in the
Ntds.dit file.

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

## DCSync

More recently, DCSync, was introduced and changed the game on dumping hashes from Domain Controllers.
The concept of DCSync is that it impersonates a Domain Controller to request all the hashes of the users in that Domain. This means, as long as you have permissions, you do not need to run any commands on the Domain Controller and you do not have to drop any files on the DC.
For DCSync to work, it is important to have the proper permissions to pull hashes from a Domain Controller. Generally limited to the Domain Admins, Enterprise Admins, Domain Controllers groups, and anyone with the Replicating Changes permissions set to Allow (i.e., Replicating Changes All/Replicating Directory Changes), DCSync will allow your user to perform this attack.

Mais recentemente, o DCSync foi introduzido e mudou o jogo no despejo de hashes de Domain Controller. O conceito do DCSync é que ele se passa por um Domain Controller para solicitar todos os hashes dos usuários daquele domínio. Isso significa que, desde que você tenha permissões, não será necessário executar nenhum comando no DC e não será necessário descartar nenhum arquivo no DC. Para que o DCSync funcione, é importante ter as permissões adequadas para extrair hashes de um DC. Geralmente limitado aos ```Domain Admins```, ```Enterprise Admins```, ```Domain Controllers groups``` e qualquer pessoa com permissões de ```Replicating Changes``` definidas como ```Allow``` (ou seja, ```Replicating Changes All```/```Replicating Directory Changes```), o DCSync permitirá que seu usuário execute este ataque.

Existem algumas formas de fazer, aqui tem exemplos:

- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync

- Modulo Empire: powershell/credentials/mimikatz/dcsync_hashdump

- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync


Empire Refs:
- https://www.ired.team/offensive-security/red-team-infrastructure/powershell-empire-101
- https://blog.harmj0y.net/empire/expanding-your-empire/