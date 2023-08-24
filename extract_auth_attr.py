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

# Load the DER file (replace this part with your own file reading code)
with open('signature.der', 'rb') as f:
    der_data = f.read()

# Find and extract the auth_attr bytes
auth_attr_bytes = find_auth_attr(der_data)

# Optionally, save the extracted auth_attr bytes to a file
with open('auth_attr.bin', 'wb') as f:
    f.write(auth_attr_bytes)

# Display the first few bytes of the extracted auth_attr for verification
hex_preview_auth_attr = binascii.hexlify(auth_attr_bytes[:256]).decode()
print(f"First few bytes of auth_attr in hex: {hex_preview_auth_attr}")
