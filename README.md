# L-Audit-Tool v1.1


## Characteristics
- Validates if "Anomnymous Bind" is enabled on the LDAP server.
- If "Anonymous Bind" is enabled, the tool tries to obtain information about the LDAP server.
- Obtain information from the LDAP server (product version, supported extensions, SASL mechanisms enabled, possible groups, possible users, possible SSL certificates, possible organizational units and more).
- Validates supported SASL mechanisms based on current security recommendations.
- Displays warnings and recommendations to improve LDAP server security.

# Requirements
- Kali Linux
- OpenLDAP (Tested against this product)
- Python 3.11
- Python Libraries
  - ldap3

# Running

`./L_Audit_Tool.py --ip ip_address`

# Disclaimer
It's important to be careful when using this tool. It has been developed for Ethical Hacking purposes, for which the author disclaims any improper or malicious use that could be exploited by third parties.
