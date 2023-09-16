import os
import base64
import pickle
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def decode_file(file_path):
    # Load the binary data from the provided file
    with open(file_path, 'rb') as file:
        data = file.read()

    # Extract the salt and encrypted data from the binary file
    salt = data[:16]
    encrypted_data = data[16:]

    # Hardcoded password from the provided code
    password = base64.b64decode(b'Y21mdHVieGk3d2x2bWgxd21ienowMHZmMXppcWV6ZjY=')

    # Generate the decryption key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=123456,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # Decrypt the data using the generated key
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data)

    # Deserialize the decrypted data using pickle
    deserialized_object = pickle.loads(decrypted_data)
    
    return deserialized_object

def decode_and_save_files(directory_path, output_directory):
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    for file in os.listdir(directory_path):
        if file.endswith('.bin'):
            try:
                decoded_content = decode_file(os.path.join(directory_path, file))
                # Convert the deserialized object to JSON and save it
                with open(os.path.join(output_directory, file.replace('.bin', '.json')), 'w') as output_file:
                    json.dump(decoded_content, output_file, indent=4)
            except Exception as e:
                print(f"Failed to decode {file} due to {str(e)}")

# Modify the paths below to point to the correct directories on your machine
current_dir = './'  # Current directory
output_dir = './odj.decoded'  # Output directory
decode_and_save_files(current_dir, output_dir)
