import unittest
import numpy as np
from he_toolkit.schemes.openfhe_wrappers.ckks_wrapper import CKKSScheme

class TestCKKSScheme(unittest.TestCase):
    def setUp(self):
        self.scheme = CKKSScheme()
        # Use small parameters for faster testing
        self.public_key, self.private_key = self.scheme.generate_keys(mult_depth=2, scale_mod_size=40, batch_size=8)

    def test_encrypt_decrypt(self):
        plaintext = [1.0, 2.0, 3.0, 4.0]
        ciphertext = self.scheme.encrypt(plaintext, self.public_key)
        decrypted = self.scheme.decrypt(ciphertext, self.private_key)
        
        # Check first few elements (CKKS decrypts to full batch size)
        for i in range(len(plaintext)):
            self.assertAlmostEqual(plaintext[i], decrypted[i].real, places=4)

    def test_homomorphic_addition(self):
        p1 = [1.0, 2.0, 3.0]
        p2 = [4.0, 5.0, 6.0]
        c1 = self.scheme.encrypt(p1, self.public_key)
        c2 = self.scheme.encrypt(p2, self.public_key)
        
        c_sum = self.scheme.add(c1, c2)
        decrypted = self.scheme.decrypt(c_sum, self.private_key)
        
        expected = [5.0, 7.0, 9.0]
        for i in range(len(expected)):
            self.assertAlmostEqual(expected[i], decrypted[i].real, places=4)

    def test_homomorphic_multiplication(self):
        p1 = [2.0, 3.0, 4.0]
        p2 = [3.0, 4.0, 5.0]
        c1 = self.scheme.encrypt(p1, self.public_key)
        c2 = self.scheme.encrypt(p2, self.public_key)
        
        c_mult = self.scheme.multiply(c1, c2)
        decrypted = self.scheme.decrypt(c_mult, self.private_key)
        
        expected = [6.0, 12.0, 20.0]
        for i in range(len(expected)):
            self.assertAlmostEqual(expected[i], decrypted[i].real, places=4)

    def test_scalar_multiplication(self):
        p = [1.0, 2.0, 3.0]
        scalar = 2.0
        c = self.scheme.encrypt(p, self.public_key)
        
        c_mult = self.scheme.multiply_scalar(c, scalar)
        decrypted = self.scheme.decrypt(c_mult, self.private_key)
        
        expected = [2.0, 4.0, 6.0]
        for i in range(len(expected)):
            self.assertAlmostEqual(expected[i], decrypted[i].real, places=4)

if __name__ == '__main__':
    unittest.main()
