import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from he_toolkit.schemes.partial.paillier import PaillierScheme

def test_paillier():
    print("Testing Paillier Scheme...")
    scheme = PaillierScheme()
    
    print("Generating keys...")
    public_key, private_key = scheme.generate_keys(key_size=1024) # Use smaller key for speed
    
    # Test Encryption/Decryption
    val1 = 5.5
    val2 = 10.2
    
    print(f"Encrypting {val1} and {val2}...")
    enc1 = scheme.encrypt(val1, public_key)
    enc2 = scheme.encrypt(val2, public_key)
    
    dec1 = scheme.decrypt(enc1, private_key)
    dec2 = scheme.decrypt(enc2, private_key)
    
    print(f"Decrypted: {dec1}, {dec2}")
    assert abs(dec1 - val1) < 1e-6
    assert abs(dec2 - val2) < 1e-6
    
    # Test Addition
    print("Testing Addition...")
    enc_sum = scheme.add(enc1, enc2)
    dec_sum = scheme.decrypt(enc_sum, private_key)
    print(f"Sum: {dec_sum} (Expected: {val1 + val2})")
    assert abs(dec_sum - (val1 + val2)) < 1e-6
    
    # Test Scalar Multiplication
    scalar = 3
    print(f"Testing Scalar Multiplication by {scalar}...")
    enc_mult = scheme.multiply_scalar(enc1, scalar)
    dec_mult = scheme.decrypt(enc_mult, private_key)
    print(f"Mult: {dec_mult} (Expected: {val1 * scalar})")
    assert abs(dec_mult - (val1 * scalar)) < 1e-6
    
    print("All tests passed!")

if __name__ == "__main__":
    test_paillier()
