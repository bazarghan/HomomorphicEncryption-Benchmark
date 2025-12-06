import unittest
from he_toolkit.schemes.openfhe_wrappers.bgv_wrapper import BGVScheme

class TestBGVScheme(unittest.TestCase):
    def setUp(self):
        self.scheme = BGVScheme()
        # Use small parameters for faster testing
        self.public_key, self.private_key = self.scheme.generate_keys(
            plain_modulus=65537,
            mult_depth=2,
            scale_mod_size=40,
            batch_size=8
        )

    def test_encrypt_decrypt(self):
        plaintext = [1, 2, 3, 4]
        ciphertext = self.scheme.encrypt(plaintext, self.public_key)
        decrypted = self.scheme.decrypt(ciphertext, self.private_key)
        
        # Check first corresponding elements
        for i in range(len(plaintext)):
            self.assertEqual(plaintext[i], decrypted[i])

    def test_homomorphic_addition(self):
        p1 = [1, 2, 3]
        p2 = [4, 5, 6]
        c1 = self.scheme.encrypt(p1, self.public_key)
        c2 = self.scheme.encrypt(p2, self.public_key)
        
        c_sum = self.scheme.add(c1, c2)
        decrypted = self.scheme.decrypt(c_sum, self.private_key)
        
        expected = [5, 7, 9]
        for i in range(len(expected)):
            self.assertEqual(expected[i], decrypted[i])

    def test_homomorphic_multiplication(self):
        p1 = [2, 3, 4]
        p2 = [3, 4, 5]
        c1 = self.scheme.encrypt(p1, self.public_key)
        c2 = self.scheme.encrypt(p2, self.public_key)
        
        c_mult = self.scheme.multiply(c1, c2)
        decrypted = self.scheme.decrypt(c_mult, self.private_key)
        
        expected = [6, 12, 20]
        for i in range(len(expected)):
            self.assertEqual(expected[i], decrypted[i])

    def test_scalar_multiplication(self):
        p = [1, 2, 3]
        scalar = 2
        c = self.scheme.encrypt(p, self.public_key)
        
        c_mult = self.scheme.multiply_scalar(c, scalar)
        decrypted = self.scheme.decrypt(c_mult, self.private_key)
        
        expected = [2, 4, 6]
        for i in range(len(expected)):
            self.assertEqual(expected[i], decrypted[i])

if __name__ == '__main__':
    unittest.main()
