import pytest
from jwt_cracker import try_brute_force_attack, verify_jwt_with_secret, try_dictionary_attack

# These are example tokens generated for each algorithm using 'supersecret'
validHS256Token = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE3MzI3NjE4OTUuMDUzMjR9.lsxx42klQkrd3qpozMfO4MQpI7zYhjE6Sy7sKNWNURE'
validHS384Token = 'eyJhbGciOiAiSFMzODQiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE3MzI3NjE4OTUuMDUzMjR9.CQgJUDaqq4Mjp3fhK7dKq7i2XNiE6iL1kesmg8bv5gUQ7B6pptBybDffBee95JLv'
validHS512Token = 'eyJhbGciOiAiSFM1MTIiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE3MzI3NjE4OTUuMDU0MjQxfQ.DCKs4HAX4IZdcpUj87PPLtQqqslCIEvxKKzoyxO03mg5D9Tj9KQyRXRfVhPPBDQCyz0Bs801LXmL_s9mFfMF6A'

def test_brute_force_HS256():
    """Test the brute-force function with HS256."""
    is_valid = verify_jwt_with_secret(validHS256Token, 'supersecret', 'HS256')
    assert is_valid == True  # Ensure the correct secret was validated

def test_brute_force_HS384():
    """Test the brute-force function with HS384."""
    is_valid = verify_jwt_with_secret(validHS384Token, 'supersecret', 'HS384')
    assert is_valid == True

def test_brute_force_HS512():
    """Test the brute-force function with HS512."""
    is_valid = verify_jwt_with_secret(validHS512Token, 'supersecret', 'HS512')
    assert is_valid == True

def test_dictionary_attack_HS256():
    """Test the dictionary attack for HS256."""
    with open('test_dictionary.txt', 'w') as f:
        f.write('password\nsupersecret\n')
    
    secret_found = try_dictionary_attack(validHS256Token, 'test_dictionary.txt', 'HS256')
    assert secret_found == 'supersecret'

def test_dictionary_attack_HS384():
    """Test the dictionary attack for HS384."""
    with open('test_dictionary.txt', 'w') as f:
        f.write('password\nsupersecret\n')

    secret_found = try_dictionary_attack(validHS384Token, 'test_dictionary.txt', 'HS384')
    assert secret_found == 'supersecret'

def test_dictionary_attack_HS512():
    """Test the dictionary attack for HS512."""
    with open('test_dictionary.txt', 'w') as f:
        f.write('password\nsupersecret\n')

    secret_found = try_dictionary_attack(validHS512Token, 'test_dictionary.txt', 'HS512')
    assert secret_found == 'supersecret'
