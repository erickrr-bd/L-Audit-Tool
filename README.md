# L-Audit-Toolv1.0
LDAP audit tool.

## Characteristics
- Validate if it's possible to make queries through "Anonymous Bind".
- If "Anonymous Bind" is allowed, the tool automatically attempts to obtain information from the LDAP server.
- Obtains information from the LDAP server (product version, supported extensions, SASL mechanisms enabled, etc).
- Validates supported SASL mechanisms based on current security recommendations.
- Displays warnings and recommendations to improve LDAP server security.

# Requirements
- Kali Linux
- OpenLDAP (Tested against this product)
- Python 3.11
- Python Libraries
  - ldap3

# Running

#Disclaimer
It's important to be careful when using this tool. It has been developed for Ethical Hacking purposes, for which the author disclaims any improper or malicious use that could be exploited by third parties.

# Commercial Support
![Tekium](https://github.com/unmanarc/uAuditAnalyzer2/blob/master/art/tekium_slogo.jpeg)

Tekium is a cybersecurity company specialized in red team and blue team activities based in Mexico, it has clients in the financial, telecom and retail sectors.

Tekium is an active sponsor of the project, and provides commercial support in the case you need it.

For integration with other platforms such as the Elastic stack, SIEMs, managed security providers in-house solutions, or for any other requests for extending current functionality that you wish to see included in future versions, please contact us: info at tekium.mx

For more information, go to: https://www.tekium.mx/
