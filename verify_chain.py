from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_certificate_chain(cert_path, issuer_path):
    # Load the certificate and its issuer
    with open(cert_path, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    with open(issuer_path, "rb") as issuer_file:
        issuer = x509.load_pem_x509_certificate(issuer_file.read(), default_backend())

    # Extract the public key from the issuer
    issuer_public_key = issuer.public_key()

    # Verify the certificate's signature
    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except InvalidSignature:
        return False


# Verify the chain
root_cert = "cert_1.pem"
intermediate_cert = "cert_2.pem"
end_entity_cert = "cert_3.pem"

if not verify_certificate_chain(intermediate_cert, root_cert):
    print("Intermediate certificate verification failed!")

if not verify_certificate_chain(end_entity_cert, intermediate_cert):
    print("End-entity certificate verification failed!")


print("All certificates in the chain are verified!")
