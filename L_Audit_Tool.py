#!/usr/bin/env python

import ssl
import ldap3
import socket
import argparse
from os import system

def validate_anonymous_authentication(ip_address, port):
	"""
	Method that validates if "ANONYMOUS BIND" is allowed for the LDAP server. If this is enabled, it lists information about the LDAP server, as well as possible users, groups, among others.
	
	:arg ip_address: Target's IP Address.
	:arg port: Target's Port.
	"""
	if port == 389:
		server = ldap3.Server(ip_address, get_info = ldap3.ALL, port = port)
	elif port == 636:
		server = ldap3.Server(ip_address, get_info = ldap3.ALL, port = port, use_ssl = True)
	connection = ldap3.Connection(server)
	if connection.bind():
		print(f"{YELLOW}[*] Warning:{END} 'Anonymous Bind' allowed. If Anonymous LDAP Binding is enabled it allows an attacker to connect and search the directory (bind and search) without logging in.\nFor more information:\nhttps://www.tenable.com/plugins/nessus/10723\n")
		if port == 389:
			print(f"{YELLOW}[*] Warning:{END} It's recommended to establish the connection using SSL. Without SSL you establish a cleartext connection, susceptible to 'man-in-the-middle' attacks.\nFor more information:\nhttps://jumpcloud.com/blog/ldap-vs-ldaps\n")
		get_information(server)
		print("\n[*] POSSIBLE ORGANIZATIONAL UNITS:")
		search_organizational_units(connection, server.info.naming_contexts[0])
		print("\n[*] POSSIBLE USERS:")
		search_users(connection, server.info.naming_contexts[0])
		print("\n[*] POSSIBLE GROUPS:")
		search_groups(connection, server.info.naming_contexts[0])
		print("\n[*] POSSIBLE CA CERTIFICATES:")
		search_ca_certificates(connection, server.info.naming_contexts[0])
		print("\n[*] POSSIBLE PASSWORD OBJECTS:")
		search_password_objects(connection, server.info.naming_contexts[0])
	else:
		print("[*] 'Anonymous Bind' not allowed. An authentication mechanism is required.")


def get_information(server):
	"""
	Method that obtains information from the LDAP server.
	
	:arg server: The object that specifies the DSA LDAP Server that will be used by the connection.
	"""
	print(f"{GREEN}[*] INFORMATION:{END}\n")
	print(f"[*] Vendor Name: {server.info.vendor_name[0]}")
	print(f"[*] Vendor Version: {server.info.vendor_version[0]}")
	print("\n[*] Supported LDAP Versions:")
	[print(f"\t{GREEN}* {item}{END}") for item in server.info.supported_ldap_versions]
	print("\n[*] Naming Contexts:")
	[print(f"\t{GREEN}* {item}{END}") for item in server.info.naming_contexts]
	print("\n[*] Supported SASL Mechanisms (https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml#sasl-mechanisms-1): ")
	validate_sasl_mechanisms(server.info.supported_sasl_mechanisms)
	print("\n[*] Supported Controls:")
	[print(f"\t{GREEN}* {item[0]} - {item[1]} - {item[2]} - {item[3]}{END}") for item in server.info.supported_controls]
	print("\n[*] Supported Extensions:")
	[print(f"\t{GREEN}* {item[0]} - {item[1]} - {item[2]} - {item[3]}{END}") for item in server.info.supported_extensions]
	print("\n[*] Supported Features:")
	[print(f"\t{GREEN}* {item[0]} - {item[1]} - {item[2]} - {item[3]}{END}") for item in server.info.supported_features]
	

def validate_sasl_mechanisms(supported_sasl_mechanisms):
	"""
	Method that validates the supported SASL mechanisms.
	
	:arg supported_sasl_mechanisms: SASL mechanism.
	"""
	for item in supported_sasl_mechanisms:
		match item:
			case "ANONYMOUS":
				print(f"\t{YELLOW}* {item} (COMMON){END}\n\tThe anonymous mechanism grants access to information by anyone.  For this reason it should be disabled by default so the administrator can make an explicit decision to enable it. (https://www.ietf.org/rfc/rfc2245.txt)")
			case "CRAM-MD5":
				print(f"\t{YELLOW}* {item} (LIMITED){END}\n\tEven with the use of CRAM, users are still vulnerable to active attacks.  An example of an increasingly common active attack is 'TCP Session Hijacking' as described in CERT Advisory CA-95:01 [CERT95]. (https://www.ietf.org/rfc/rfc2195.txt)")
			case "DIGEST-MD5":
				print(f"\t{YELLOW}* {item} (OBSOLETE){END}\n\tDigest Authentication does not provide a strong authentication mechanism, when compared to public key based mechanisms, for example. (https://www.ietf.org/rfc/rfc2831.txt)")
			case "PLAIN":
				print(f"\t{YELLOW}* {item} (COMMON){END}\n\tBy default, implementations SHOULD NOT advertise and SHOULD NOT make use of the PLAIN mechanism unless adequate data security services are in place. (https://www.rfc-editor.org/rfc/rfc4616.html)")
			case "LOGIN":
				print(f"\t{YELLOW}* {item} (OBSOLETE){END}\n\tThe LOGIN mechanism MUST NOT be advertised or used in any configuration that prohibits the PLAIN mechanism or a plaintext LOGIN (or USER/PASS) command that sends passwords in the clear. (https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00)")
			case "EXTERNAL":
				print(f"\t{GREEN}* {item} (COMMON){END}\n\thttps://www.rfc-editor.org/rfc/rfc4422.html")
			case "GSSAPI":
				print(f"\t{GREEN}* {item} (COMMON){END}\n\thttps://www.rfc-editor.org/rfc/rfc4752.html")
			case "GSS-SPNEGO":
				print(f"\t{GREEN}* {item} (LIMITED){END}")
			case _:
				print(f"\t{GREEN}* {item}{END}")


def search_users(connection, search_base):
	"""
	Method that searches for usernames.

	:arg connection: Object used to send operation requests to the LDAP server.
	:arg search_base: The base of the search request.  
	"""
	users = []
	connection.search(search_base = search_base, search_filter = "(|(objectClass=posixAccount)(objectClass=person))", search_scope = "SUBTREE", attributes = ["uid"])
	[users.append(entry["attributes"]["uid"][0]) for entry in connection.response]
	users = list(dict.fromkeys(users))
	[print(f"\t{GREEN}* {user}{END}") for user in users]


def search_groups(connection, search_base):
	"""
	Method that searches for groups.

	:arg connection: Object used to send operation requests to the LDAP server.
	:arg search_base: The base of the search request.  
	"""
	groups = []
	connection.search(search_base = search_base, search_filter = "(|(objectClass=posixgroup)(objectClass=groupOfNames))", search_scope = "SUBTREE", attributes = ["cn"])
	[groups.append(entry["attributes"]["cn"][0]) for entry in connection.response]
	groups = list(dict.fromkeys(groups))
	[print(f"\t{GREEN}* {group}{END}") for group in groups]


def search_ca_certificates(connection, search_base):
	"""
	Method that searches for CA certificates.

	:arg connection: Object used to send operation requests to the LDAP server.
	:arg search_base: The base of the search request.  
	"""
	connection.search(search_base = search_base, search_filter = "(objectClass=pkiCA)", search_scope = "SUBTREE", attributes = ["cn"])
	[print(f"\t{GREEN}* {entry['attributes']['cn'][0]}{END}\n\t{entry['dn']}") for entry in connection.response]


def search_organizational_units(connection, search_base):
	"""
	Method that searches for Organizational Units.

	:arg connection: Object used to send operation requests to the LDAP server.
	:arg search_base: The base of the search request.  
	"""
	connection.search(search_base = search_base, search_filter = "(objectClass=organizationalUnit)", search_scope = "SUBTREE")
	[print(f"\t{GREEN}* {entry['dn']}{END}") for entry in connection.response]


def search_password_objects(connection, search_base):
	"""
	Method that searches for possible objects related to passwords.

	:arg connection: Object used to send operation requests to the LDAP server.
	:arg search_base: The base of the search request. 
	"""
	connection.search(search_base = search_base, search_filter = "(cn=*pass*)", search_scope = "SUBTREE", attributes = ["cn"])
	[print(f"\t{GREEN}* {entry['attributes']['cn'][0]}{END}\n\t{entry['dn']}") for entry in connection.response]


RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"
YELLOW = "\033[0;33m"
PURPLE = '\033[0;35m' 
CYAN = "\033[36m"
END = "\033[0m"
WHITE = "\033[0;37m"

BANNER = f"""
{GREEN}	
 _           ___  _   _______ _____ _____   _____ _____  _____ _     
| |         / _ \| | | |  _  \_   _|_   _| |_   _|  _  ||  _  | |    
| |  ______/ /_\ \ | | | | | | | |   | |     | | | | | || | | | |    
| | |______|  _  | | | | | | | | |   | |     | | | | | || | | | |    
| |____    | | | | |_| | |/ / _| |_  | |     | | \ \_/ /\ \_/ / |____
\_____/    \_| |_/\___/|___/  \___/  \_/     \_/  \___/  \___/\_____/v1.1
By Erick Rodríguez                                                                                                                                                                                          	
{END}
"""
system("clear")
print(f"{YELLOW}------------------------------------------------------------------------------------------------------------{END}")
print(BANNER)
print(f"{YELLOW}------------------------------------------------------------------------------------------------------------{END}")
print("Author: Erick Roberto Rodriguez Rodriguez")
print("Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com")
print("GitHub: https://github.com/erickrr-bd/L-Audit-Tool")
print("L-Audit Tool v1.1 - November 2024\n")

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help = "Target's LDAP IP Address")
args = parser.parse_args()

print(f"[*] IP Address: {args.ip}\n")

print(f"{CYAN}[*] Validating 'Anonymous Bind' Port: 389{END}\n")
validate_anonymous_authentication(args.ip, 389)

print(f"\n{CYAN}[*] Validating 'Anonymous Bind' Port: 636{END}\n")
validate_anonymous_authentication(args.ip, 636)
