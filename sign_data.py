from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Load the private key from PEM file
with open("cert_4.pem", "rb") as key_file:
    private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

# Data to sign
data = b"Your data to sign here"

# Sign data
signature = private_key.sign(
    data,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Print signature in hexadecimal format
print("Signature: ", signature.hex())
