Get all the .exes in Program files which have Everyone and User permissions:

```powershell

$svcs = Get-CimInstance Win32_Service; Get-ChildItem "C:\Program Files" -Recurse -Include *.exe -File -ErrorAction SilentlyContinue | ForEach-Object {
    $f=$_.FullName.ToLower()
    $svcMatch = $svcs | Where-Object { $_.PathName -and $_.PathName.ToLower().Contains($f) }
    if ($svcMatch) {
        $fileACL=Get-Acl $f
        $dirACL=Get-Acl (Split-Path $f)
        $fileGroups = $fileACL.Access | Where-Object { ($_.IdentityReference -match 'Everyone|Authenticated Users') -and ($_.FileSystemRights.ToString() -match 'Write|FullControl') } | ForEach-Object { "$($_.IdentityReference) ($($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value))" }
        $dirGroups = $dirACL.Access | Where-Object { ($_.IdentityReference -match 'Everyone|Authenticated Users') -and ($_.FileSystemRights.ToString() -match 'FullControl') } | ForEach-Object { "$($_.IdentityReference) ($($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value))" }
        if ($fileGroups -or $dirGroups) {
            Write-Output "Path : $f"
            Write-Output "Used by services : $($svcMatch.DisplayName -join ', ')"
            if ($fileGroups) { Write-Output "File write allowed for groups : $($fileGroups -join ', ')" }
            if ($dirGroups) { Write-Output "Full control of directory allowed for groups : $($dirGroups -join ', ')" }
            Write-Output ""
        }
    }
}
```
