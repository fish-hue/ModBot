import hashlib
import os

def check_file_integrity(file_path, expected_hash, hash_algorithm='sha256'):
    """
    Check if the file's hash matches the expected hash.
    
    :param file_path: Path to the file to be checked.
    :param expected_hash: The expected hash value (e.g., SHA256) of the file.
    :param hash_algorithm: The hashing algorithm to use (default is SHA256).
    :return: True if the file's hash matches the expected hash, else False.
    """
    try:
        # Supported hash algorithms
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }

        # Check if the chosen algorithm is supported
        if hash_algorithm not in hash_functions:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

        # Initialize the hash function
        hash_func = hash_functions[hash_algorithm]()

        # Open the file and calculate the hash
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):  # Read the file in chunks to handle large files
                hash_func.update(chunk)

        # Get the calculated hash in hexadecimal form
        file_hash = hash_func.hexdigest()

        # Compare the calculated hash with the expected hash
        if file_hash.lower() == expected_hash.lower():
            return True
        else:
            return False

    except Exception as e:
        print(f"Error checking file integrity: {e}")
        return False

def check_software_integrity(expected_version, installed_version):
    """
    Check if the installed software version matches the expected version.
    
    :param expected_version: The expected software version.
    :param installed_version: The installed software version.
    :return: True if the versions match, else False.
    """
    if installed_version == expected_version:
        return True
    else:
        return False
