# Verify that a signature was generated over some data by a specific public key
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Util.number import bytes_to_long, long_to_bytes
from cryptography.hazmat.primitives import serialization
import binascii

def parse_asn1_length(data, offset):
    length = data[offset]
    new_offset = offset + 1

    if length & 0x80:
        length_bytes = length & 0x7F
        length = int.from_bytes(data[new_offset:new_offset + length_bytes], byteorder='big')
        new_offset += length_bytes

    return length, new_offset

def find_auth_attr(data):
    SEQUENCE_TAG = 0x30
    offset = 0
    sequence_counter = 0
    in_signer_info = False
    start_pos = None
    end_pos = None

    while offset < len(data):
        if data[offset] == SEQUENCE_TAG:
            length, new_offset = parse_asn1_length(data, offset + 1)
            sequence_counter += 1

            if in_signer_info and sequence_counter == 3:
                start_pos = offset
                end_pos = new_offset + length

            offset = new_offset + length
        else:
            offset += 1

        if sequence_counter >= 2:
            in_signer_info = True

        if start_pos is not None and end_pos is not None:
            break

    if start_pos is not None and end_pos is not None:
        return data[start_pos:end_pos]
    else:
        return None

def get_pub_key(cert_name):
    # Load the certificate
    with open(cert_name, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    # Extract the public key from the certificate
    return cert.public_key()

def get_signed_data(file_name, byte_range):
    # Load the ByteRange contents from a PDF file
    with open(file_name, "rb") as pdf_file:
        pdf_contents = pdf_file.read()

    # Extract the signed data from the PDF 0:146377, 211913:211913+4932
    signed_data = pdf_contents[byte_range[0]:byte_range[1]] + pdf_contents[byte_range[2]:byte_range[2] + byte_range[3]]

    return signed_data

# dummmy sign
# cert_name = "cert_4.pem"
# signature = ".."  
# signed_data = b"Your data to sign here"
# hash_algo = hashes.SHA256()

# file_name = "aadhaar.pdf"
# cert_name = "cert_5.pem"
# byte_range = [0, 569082, 569604, 7324]
# hash_algo = hashes.SHA1()
# signature = "..."


file_name = "input.pdf"
cert_name = "cert_3.pem"
byte_range = [0, 146377, 211913, 4932]
hash_algo = hashes.SHA256()
signature = "..."


public_key = get_pub_key(cert_name)
signed_data = get_signed_data(file_name, byte_range)

# Load the DER file (replace this part with your own file reading code)
with open('signature.der', 'rb') as f:
    der_data = f.read()

# Find and extract the auth_attr bytes
auth_attr_bytes = find_auth_attr(der_data)

# Display the first few bytes of the extracted auth_attr for verification
hex_preview_auth_attr = binascii.hexlify(auth_attr_bytes[:256]).decode()
print(f"First few bytes of auth_attr in hex: {hex_preview_auth_attr}")

# print sha256 of signed data
# Calculate the SHA-256 hash of the signed data
digest = hashes.Hash(hash_algo, default_backend())
digest.update(signed_data)
digest.update(auth_attr_bytes)
hash_of_signed_data = digest.finalize()

# Decrypt and print output
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
rsa_key = RSA.import_key(pem)

# Manually "decrypt" the signature using the RSA public key
decrypted_long = pow(bytes_to_long(bytes.fromhex(signature)), rsa_key.e, rsa_key.n)
decrypted_data = long_to_bytes(decrypted_long)

# Print the decrypted data and the hash for comparison
print("Decrypted signature:", decrypted_data.hex())
print("SHA256 of signed data:", hash_of_signed_data.hex())

# Compare the last bytes (length of SHA256 hash) of decrypted_data to the hash_of_signed_data
if decrypted_data[-len(hash_of_signed_data):] == hash_of_signed_data:
    print("Decrypted data matches hash!")
else:
    print("Mismatch between decrypted data and hash!")



# Verify the signature
try:
    public_key.verify(
        bytes.fromhex(signature),       
        signed_data,                    
        padding.PKCS1v15(),             
        hash_algo                       
    )
    print("Signature verified!")
except InvalidSignature:
    print("Signature verification failed!")