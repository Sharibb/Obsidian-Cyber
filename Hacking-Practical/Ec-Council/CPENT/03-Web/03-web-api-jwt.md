# Module: Web / API / JWT

## Topics

- JWT attacks: alg:none bypass, key confusion (RS256 to HS256), weak secret brute force
- API-specific flaws: BOLA (broken object level authorization), mass assignment, rate limit bypass
- GraphQL introspection abuse
- Authentication and session management flaws
- Unsafe deserialization (conceptual understanding of Java/PHP/.NET gadget chains)
- Standard web vuln classes: SQLi, XSS, injection variants, logic flaws

## Tools

- jwt_tool (JWT attack automation)
- hashcat (JWT secret brute force)
- Burp Suite (proxying, repeater, intruder for API fuzzing)
- Postman (API enumeration/testing)

## Practice Resources

- PortSwigger Web Security Academy: JWT labs, API testing labs
- OWASP API Security Top 10 as a checklist

## Study Sequence

1. Complete PortSwigger JWT lab set end-to-end
2. Complete PortSwigger API-specific lab set
3. Practice BOLA/mass assignment identification on a deliberately vulnerable API (e.g. crAPI, VAmPI)
4. Review deserialization attack concepts at a level sufficient to recognize and report, not necessarily build custom gadget chains from scratch
