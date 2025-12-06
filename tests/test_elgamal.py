import unittest
from he_toolkit.schemes.partial.elgamal import ElGamalScheme

class TestElGamalScheme(unittest.TestCase):
    def setUp(self):
        self.scheme = ElGamalScheme()
        # Use small key size for faster testing
        self.public_key, self.private_key = self.scheme.generate_keys(key_size=128)

    def test_encrypt_decrypt_large_plaintext(self):
        # Standard ElGamal can decrypt any size plaintext
        plaintext = 12345678901234567890.0
        ciphertext = self.scheme.encrypt(plaintext, self.public_key)
        decrypted = self.scheme.decrypt(ciphertext, self.private_key)
        self.assertEqual(plaintext, decrypted)

    def test_homomorphic_multiplication(self):
        m1 = 10.0
        m2 = 20.0
        c1 = self.scheme.encrypt(m1, self.public_key)
        c2 = self.scheme.encrypt(m2, self.public_key)
        
        c_mult = self.scheme.multiply(c1, c2)
        decrypted_mult = self.scheme.decrypt(c_mult, self.private_key)
        
        self.assertEqual(m1 * m2, decrypted_mult)

    def test_homomorphic_addition_fails(self):
        # Standard ElGamal does not support addition
        c1 = self.scheme.encrypt(10, self.public_key)
        c2 = self.scheme.encrypt(20, self.public_key)
        with self.assertRaises(NotImplementedError):
            self.scheme.add(c1, c2)

    def test_scalar_multiplication_fails(self):
        # Standard ElGamal does not support scalar multiplication (in the additive sense)
        c = self.scheme.encrypt(10, self.public_key)
        with self.assertRaises(NotImplementedError):
            self.scheme.multiply_scalar(c, 5)

if __name__ == '__main__':
    unittest.main()
