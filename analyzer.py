import os
from pyasn1_modules import rfc2459
from pyasn1_modules import pem
from pyasn1_modules.rfc2459 import id_at_commonName as OID_COMMON_NAME
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.univ import ObjectIdentifier
from pyasn1_modules.rfc2437 import sha1WithRSAEncryption
from Crypto.Hash import SHA as SHA1, SHA256, SHA384, SHA512
from pyasn1_modules.rfc2437 import RSAPublicKey
from pyasn1_modules.rfc2459 import id_ce_keyUsage as OID_EXT_KEY_USAGE, KeyUsage
import sys

CERT_DIR = ''

rsa_signing_algorithms = {
    sha1WithRSAEncryption: SHA1,  # defined in RFC 2437 (obsoleted by RFC 3447)
    ObjectIdentifier('1.2.840.113549.1.1.11'): SHA256,  # defined in RFC 3447
    ObjectIdentifier('1.2.840.113549.1.1.12'): SHA384,  # defined in RFC 3447
    ObjectIdentifier('1.2.840.113549.1.1.13'): SHA512}  # defined in RFC 3447

def from_bitstring_to_bytes(bs):
    i = int("".join(str(bit) for bit in bs), base=2)
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def print_version(tbs_cert):
    version = tbs_cert['version']
    print('Version: ' + version.prettyPrint())

def print_serialNumber(tbs_cert):
    serial_number = tbs_cert['serialNumber']
    print('Serial Number: ' + serial_number.prettyPrint())

def print_issuer(tbs_cert):
    value = None
    issuer = tbs_cert['issuer'].getComponent()
    for relative_distinguished_name in issuer:
        for attribute_type_and_value in relative_distinguished_name:
            oid = attribute_type_and_value['type']
            if oid == OID_COMMON_NAME:
                value = attribute_type_and_value['value']
    ds, rest = der_decoder.decode(value, asn1Spec=rfc2459.DirectoryString())
    print('Issuer: ' + ds.getComponent().prettyPrint())

def print_validity(tbs_cert):
    validity = tbs_cert['validity']
    notBefore = validity['notBefore'].getComponent()
    notAfter = validity['notAfter'].getComponent()
    print('Validity: ' + 'From: ' + str(notBefore.asDateTime) + ' To: ' + str(notAfter.asDateTime))

def get_subject(tbs_cert):
    value = None
    issuer = tbs_cert['subject'].getComponent()
    for relative_distinguished_name in issuer:
        for attribute_type_and_value in relative_distinguished_name:
            oid = attribute_type_and_value['type']
            if oid == OID_COMMON_NAME:
                value = attribute_type_and_value['value']
    ds, rest = der_decoder.decode(value, asn1Spec=rfc2459.DirectoryString())
    return ds.getComponent()

def print_subject(tbs_cert):
    print("Subject: " + get_subject(tbs_cert).prettyPrint())

def print_summary(tbs_cert):
        print_version(tbs_cert)
        print_serialNumber(tbs_cert)
        print_issuer(tbs_cert)
        print_subject(tbs_cert)
        print_validity(tbs_cert)

def get_public_key(tbs_cert):
    subjectPublicKeyInfo = tbs_cert['subjectPublicKeyInfo']
    return subjectPublicKeyInfo

def add_in_keys_dictionary(keys_dictionary, tbs_cert):
    if (can_be_used_for_signing_certificates(tbs_cert) == 1):
        print("CAN be used for signing certificates")
        subjectPublicKey = get_public_key(tbs_cert)
        subject = get_subject(tbs_cert)
        keys_dictionary.update({subject: subjectPublicKey})

def print_keys_dictionary(keys_dictionary):
    for key, value in keys_dictionary.items():
        print(key, value)

def find_key_usage(extensions):
    return next(e['extnValue'] for e in extensions if e['extnID'] == OID_EXT_KEY_USAGE)

def can_be_used_for_signing_certificates(tbs_cert):
    extensions = tbs_cert['extensions']
    ku_ext = find_key_usage(extensions)
    octet_stream, rest = der_decoder.decode(ku_ext)
    ku, rest = der_decoder.decode(octet_stream, asn1Spec=KeyUsage())
    key_cert_bit = KeyUsage.namedValues.getValue('keyCertSign')
    try:
        return(ku[key_cert_bit])
    except Exception as e:
        print("CAN'T be used for signing certificates")
        return False

def get_exp_and_mod(subject_pk):
    algorithm_oid = subject_pk['algorithm']['algorithm']
    #algorithm_oid == OID_RSA_ENCRYPTION
    pk = from_bitstring_to_bytes(subject_pk['subjectPublicKey'])
    rsa_pk, rest = der_decoder.decode(pk, asn1Spec=RSAPublicKey())
    return rsa_pk['publicExponent'], rsa_pk['modulus']

def signature_check(cert, keys_dictionary):
    tbs_cert = cert['tbsCertificate']
    print('Verifying certificate for ' + get_subject(tbs_cert))
    if is_self_signed(tbs_cert) == True:
        print('Self-Signed Certificate')
        print()
        return
    signature_algo = cert['signatureAlgorithm']
    algo_oid = signature_algo['algorithm']
    sv = cert['signatureValue']
    signature_value = int("".join(str(bit) for bit in sv), base=2)
    rsa_signing_algorithm = rsa_signing_algorithms[algo_oid].new()
    rsa_signing_algorithm.update(der_encoder.encode(tbs_cert))
    digest_tbs_cert = rsa_signing_algorithm.hexdigest()
    issuerName = get_issuer(tbs_cert)
    issuerPublicKey = keys_dictionary.get(issuerName)
    issuer_exponent, issuer_modulus = get_exp_and_mod(issuerPublicKey)
    signed_value = pow(signature_value, int(issuer_exponent), int(issuer_modulus))
    sv = hex(signed_value)
    print("Signed by "+issuerName if digest_tbs_cert in sv else "WARNING")
    print()

def get_issuer(tbs_cert):
    value = None
    issuer = tbs_cert['issuer'].getComponent()
    for relative_distinguished_name in issuer:
        for attribute_type_and_value in relative_distinguished_name:
            oid = attribute_type_and_value['type']
            if oid == OID_COMMON_NAME:
                value = attribute_type_and_value['value']
    ds, rest = der_decoder.decode(value, asn1Spec=rfc2459.DirectoryString())
    return ds.getComponent().prettyPrint()

def is_self_signed(tbs_cert):
    subject = get_subject(tbs_cert)
    issuer = get_issuer(tbs_cert)
    if subject == issuer:
        return True
    return False

def play():
    keys_dictionary = {}
    certificates_list = list()
    for data_file in os.listdir(CERT_DIR):  #first round
        filename = os.path.join(CERT_DIR, data_file)
        with open(filename) as f:
            binary_data = pem.readPemFromFile(f)
            cert, rest = der_decoder.decode(binary_data, asn1Spec=rfc2459.Certificate())
            tbs_cert = cert['tbsCertificate']
            certificates_list.append(cert)
            print_summary(tbs_cert)
            add_in_keys_dictionary(keys_dictionary,tbs_cert)
            print()
    for c in certificates_list: #second round
        signature_check(c, keys_dictionary)

if __name__ == '__main__':
    CERT_DIR = sys.argv[1] #taking as argument the absolute path of the directory which contains certificates
    play()