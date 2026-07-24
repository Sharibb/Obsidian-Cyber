# Module: Cloud

Lighter weight in CPENT relative to AD/web, but present.

## Topics

- AWS/Azure IAM misconfiguration and privilege escalation paths
- S3 bucket exposure and misconfigured public access
- Instance metadata service abuse via SSRF (169.254.169.254)
- Common cloud service misconfig patterns (overly permissive roles, exposed secrets in config)

## Tools

- AWS CLI / Azure CLI for enumeration
- ScoutSuite or Prowler (cloud config auditing, for study/reference)
- Pacu (AWS exploitation framework, for lab practice)

## Practice Resources

- HTB Cloud-tagged content
- flAWS / flAWS2 (AWS misconfig practice wargame)

## Study Sequence

1. Walk through flAWS/flAWS2 end-to-end
2. Practice identifying and abusing an SSRF-to-metadata-service path in a lab
3. Review common IAM privesc paths (PassRole, overly broad policies) at a conceptual level
