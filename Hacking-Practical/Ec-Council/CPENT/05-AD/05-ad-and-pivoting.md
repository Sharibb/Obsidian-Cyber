# Module: Active Directory + Pivoting/Tunneling

## Topics

- AD attack paths: Kerberoasting, ASREPRoasting, delegation abuse (unconstrained/constrained/RBCD), ACL abuse
- Credential access: SAM dumping, LSASS access, DCSync
- Windows/Linux privilege escalation: token impersonation (SeImpersonatePrivilege to SYSTEM via PrintSpoofer/GodPotato), sudo misconfigs, kernel exploit awareness
- Pivoting/tunneling: SSH tunnels, SOCKS proxying, double pivot across 2+ network segments

## Tools

- BloodHound / SharpHound (AD path enumeration)
- Mimikatz (credential access, DCSync)
- Evil-WinRM, impacket suite
- Ligolo-ng, Chisel, proxychains (pivoting)

## Focus for CPENT

This is typically the strongest-covered area from prior AD-focused training. Priority here is chaining, not individual technique review:

- Full attack chain: initial AD foothold → lateral movement → domain compromise → pivot into a second segment → escalate again in that segment
- Blind double pivot practice (chaining 2+ hops without direct visibility into the final segment)
- Timed full-chain runs, not isolated single-box exercises

## Practice Resources

- HTB Pro Labs (multi-segment AD environments)
- Existing AD lab environments already in progress, extended to include a pivot-and-escalate-again scenario
