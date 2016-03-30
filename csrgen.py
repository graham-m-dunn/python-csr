#!/usr/bin/env python
#
# Generate a key, self-signed certificate, and certificate request.
# Usage: csrgen <fqdn>
# 
# When more than one hostname is provided, a SAN (Subject Alternate Name)
# certificate and request are generated.  This can be acheived by adding -s.
# Usage: csrgen <hostname> -s <san0> <san1>
#
# Author: Courtney Cotton <cotton@cottoncourtney.com> 06-25-2014

# Libraries/Modules
import argparse

from OpenSSL import crypto


def generate_csr(nodename, alternate_names=None):
    """
    # Generate Certificate Signing Request (CSR)
    :param alternate_names:
    :param nodename:
    :return:
    """

    # while True:
    #   C  = raw_input("Enter your Country Name (2 letter code) [US]: ")
    #   if len(C) != 2:
    #     print "You must enter two letters. You entered %r" % (C)
    #     continue
    #   ST = raw_input("Enter your State or Province <full name> []:California: ")
    #   if len(ST) == 0:
    #     print "Please enter your State or Province."
    #     continue
    #   L  = raw_input("Enter your (Locality Name (eg, city) []:San Francisco: ")
    #   if len(L) == 0:
    #     print "Please enter your City."
    #     continue
    #   O  = raw_input("Enter your Organization Name (eg, company) []:FTW Enterprise: ")
    #   if len(L) == 0:
    #      print "Please enter your Organization Name."
    #      continue
    #   OU = raw_input("Enter your Organizational Unit (eg, section) []:IT: ")
    #   if len(OU) == 0:
    #     print "Please enter your OU."
    #     continue

    # Allows you to permanently set values required for CSR
    # To use, comment raw_input and uncomment this section.
    if alternate_names is None:
        alternate_names = []
    country = 'CA'
    state = 'Ontario'
    locality = 'Waterloo'
    organization = 'Kik Interactive Inc.'
    organizational_unit = 'Kik IT'

    csrfile = nodename + '.csr'
    keyfile = nodename + '.key'

    # Appends SAN to have 'DNS:'
    ss = []
    for i in alternate_names:
        ss.append("DNS: %s" % i)
    ss = ", ".join(ss)

    req = crypto.X509Req()
    req.get_subject().CN = nodename
    req.get_subject().countryName = country
    req.get_subject().stateOrProvinceName = state
    req.get_subject().localityName = locality
    req.get_subject().organizationName = organization
    req.get_subject().organizationalUnitName = organizational_unit
    # Add in extensions
    base_constraints = ([
        crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
    ])
    x509_extensions = base_constraints
    # If there are SAN entries, append the base_constraints to include them.
    if ss:
        san_constraint = crypto.X509Extension("subjectAltName", False, ss)
        x509_extensions.append(san_constraint)
    req.add_extensions(x509_extensions)
    # Utilizes generate_key function to kick off key generation.
    key = generate_key(crypto.TYPE_RSA, 2048)
    req.set_pubkey(key)
    req.sign(key, "sha1")
    generate_files(csrfile, req)
    generate_files(keyfile, key)
    return req


def generate_key(crypto_type, bits):
    """
    Generate Private Key

    :param crypto_type:
    :param bits:
    :return:
    """
    key = crypto.PKey()
    key.generate_key(crypto_type, bits)
    return key


def generate_files(mk_file, request):
    """
    Generate .csr/key files.

    :rtype: None
    :param mk_file:
    :param request:
    """
    if mk_file[-3:] == 'csr':
        f = open(mk_file, "w")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))
        f.close()
        print crypto.dump_certificate_request(crypto.FILETYPE_PEM, request)
    elif mk_file[-3:] == 'key':
        # TODO: App Engine wants an unencrypted pem file
        # https://cloud.google.com/appengine/docs/python/console/using-custom-domains-and-ssl
        # openssl rsa -in myserver.key -out myserver.key.pem
        f = open(mk_file, "w")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
        f.close()
    else:
        print "Failed."
        exit()


if __name__ == "__main__":
    # Run Portion
    parser = argparse.ArgumentParser()

    parser.add_argument("name", help="Provide the FQDN", action="store")
    parser.add_argument("-s", "--san", help="SANS", action="store", nargs='*', default="")
    args = parser.parse_args()

    hostname = args.name
    sans = args.san

    generate_csr(hostname, sans)