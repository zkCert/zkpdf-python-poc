# ZK Doc Verification

### Setup
1. Run `python3 extract_sig.py` to extract the signature from the input PDF file. Copy the 'Contents' value into a file called 'signature.hex'
2. Run `xxd -r -p signature.hex > signature.der` to convert to binary
3. Run `openssl pkcs7 -inform DER -in signature.der -print_certs > certs.pem` to save the certificate to `certs.pem`
4. Run `python3 split_certs.py` to split the certificates into individual files
5. Run `openssl x509 -in cert_XXX.pem -text -noout` to view the certificate contents where `XXX` is 1 2 or 3
6. Run `python3 verify_sig.py` to verify the signature
7. Run `openssl pkcs7 -inform DER -in signature.der -print` to view the signature contents

### Verification


### Certificate Chain of Trust
1. To verify the root certificate:
    1. From the root certificate, the SignatureValue signs all the data in the self certificate except the SignatureValue and SignatureAlgorithm (called the "to-be-signed")
    2. The root SignatureAlgorithm is the RSA + SHA algorithm that is used
    3. Check that the SignatureValue decrypted with the Modulus matches the hash of the "to-be-signed" data
2. To verify the intermediate certificate, the same process is repeated, except the SignatureValue is signed by the pub key of the root certificate
3. Signature Regex
    1. Nice to have - Extract Not Before and Not After timestamps
    2. Extract Modulus and Exponent
4. Content Regex
    1. Nice to have, maybe just compute hash according to byte start / end array?
5. Edge cases
    1. Certificate may have been revoked
    2. X.509v3 extensions can contain additional constraints or data that can influence the validity or usage of the certificate. Ensure you understand and validate any critical extensions present in the certificate.
