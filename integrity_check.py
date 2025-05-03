# integrity_check.py

import hashlib
import requests

def check_file_integrity(file_url, expected_hash, hash_algorithm='sha256'):
    try:
        response = requests.get(file_url, stream=True)
        response.raise_for_status()
        hash_func = hashlib.new(hash_algorithm)
        for chunk in response.iter_content(1024):
            hash_func.update(chunk)
        return hash_func.hexdigest() == expected_hash
    except Exception as e:
        print(f"Error checking integrity of {file_url}: {e}")
        return False

def check_software_integrity(expected_version, installed_version):
    return expected_version == installed_version
