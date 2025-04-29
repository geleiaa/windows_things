## ldap logs in eventviewer (lab env)
> ___

- https://www.manageengine.com/products/active-directory-audit/how-to/how-to-monitor-active-directory-ldap-logs.html

```powershell
Get-WinEvent -LogName "Directory Service" -MaxEvents 50 | Where-Object { $_.Message -like "*LDAP*" }
```


#### make queries through LDAPS (ldap + ssl)

- to do this you need verify if AD server has ldaps running (commonly on port 636)

```powershell
$ldapServer = "ldaps://dc01.domain.com:636"
$baseDN = "DC=domain,DC=com"

# Creds (opcional — if you auth with another user)
$cred = Get-Credential

# Create entry object LDAP via LDAPS
$entry = New-Object System.DirectoryServices.DirectoryEntry($ldapServer/$baseDN, $cred.UserName, $cred.GetNetworkCredential().Password)

# Create Searcher
$searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
$searcher.Filter = "(objectClass=user)"
$searcher.SearchScope = "Subtree"

# run query
$searcher.FindAll()
```

```
Write-Host "Monitorando logs do PowerShell (Microsoft-Windows-PowerShell/Operational)..."

while ($true) {
    Get-WinEvent -LogName Security -MaxEvents 1 | 
        Sort-Object TimeCreated | 
        Select-Object TimeCreated, Message
    Start-Sleep -Seconds 2
}
```
