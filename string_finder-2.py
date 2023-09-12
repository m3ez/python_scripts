import sys
from tabulate import tabulate
import codecs
from urllib.parse import quote, unquote
import binascii
import base64
import base58   # Install using pip install base58
import base91   # Install using pip install base91
import punycode # Install using pip install punycode

def bytes_(b):
    """Reverse a bytes-like object."""
    return bytes(b)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <input_text>")
        sys.exit(1)

    input_text = sys.argv[1].rstrip()

    # Table for encoding results
    table_data = []

    # Add ROT13
    rot13 = codecs.encode(input_text, 'rot_13')
    result_r = rot13[::-1]  # Reverse the ROT13 text
    table_data.append(["rot13", rot13, result_r])

    # Add URL Encoding
    url_encoded = quote(input_text)
    table_data.append(["url", url_encoded, unquote(url_encoded)[::-1]])

    # Add Caesar Cipher (Shift by 3 positions)
    def caesar_cipher(text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                shifted = ord(char) + shift
                if char.islower():
                    if shifted > ord('z'):
                        shifted -= 26
                    elif shifted < ord('a'):
                        shifted += 26
                elif char.isupper():
                    if shifted > ord('Z'):
                        shifted -= 26
                    elif shifted < ord('A'):
                        shifted += 26
                result += chr(shifted)
            else:
                result += char
        return result

    caesar_shifted = caesar_cipher(input_text, 3)
    table_data.append(["caesar", caesar_shifted, caesar_shifted[::-1]])

    # Add HEX (0x notation)
    hex_txt = '0x' + ''.join([f'{ord(char):02X}' for char in input_text])
    hex_txt_str = hex_txt
    table_data.append(["hex (0x)", hex_txt_str, hex_txt_str[::-1]])

    # Add Binary (0s and 1s)
    binary_txt = ' '.join([format(ord(char), '08b') for char in input_text])
    binary_txt_str = binary_txt
    table_data.append(["binary (01)", binary_txt_str, binary_txt_str[::-1]])

    # Add Base16 Encoding
    base16_encoded = binascii.hexlify(input_text.encode('utf-8')).decode('utf-8')
    table_data.append(["base16", base16_encoded, base16_encoded[::-1]])

    # Add Base32 Encoding
    base32_encoded = base64.b32encode(input_text.encode('utf-8')).decode('utf-8')
    table_data.append(["base32", base32_encoded, base32_encoded[::-1]])

    # Add Base64 Encoding
    base64_encoded = base64.b64encode(input_text.encode('utf-8')).decode('utf-8')
    table_data.append(["base64", base64_encoded, base64_encoded[::-1]])

    # Add Base2 (Binary) Encoding
    base2_encoded = ' '.join([format(ord(char), '08b') for char in input_text])
    table_data.append(["base2", base2_encoded, base2_encoded[::-1]])

    # Add Base58 Encoding
    base58_encoded = base58.b58encode(input_text.encode('utf-8')).decode('utf-8')
    table_data.append(["base58", base58_encoded, base58_encoded[::-1]])

    # Print the table
    table_headers = ["Attribute", "Result", "Result (Reversed)"]
    print("\nEncoded Results:")
    print(tabulate(table_data, headers=table_headers, tablefmt="pretty"))

if __name__ == '__main__':
    main()
