# Read the uploaded file content
with open("certs.pem", "r") as file:
    content = file.read()

# Split the content by the END CERTIFICATE line
certs_split = content.split("-----END CERTIFICATE-----")

# Filter out empty strings and append the END CERTIFICATE line back
certs_split = [cert.strip() + "\n-----END CERTIFICATE-----" for cert in certs_split if cert.strip()]

# Save each certificate to a separate file
cert_files = []
for idx, cert in enumerate(certs_split):
    filename = f"cert_{idx + 1}.pem"
    with open(filename, 'w') as f:
        f.write(cert)
    cert_files.append(filename)

cert_files