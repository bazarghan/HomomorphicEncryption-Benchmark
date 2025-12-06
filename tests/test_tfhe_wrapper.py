import unittest
from he_toolkit.schemes.openfhe_wrappers.tfhe_wrapper import TFHEScheme

class TestTFHEScheme(unittest.TestCase):
    def setUp(self):
        self.scheme = TFHEScheme()
        # Use TOY security level for faster testing if available, else standard
        try:
           from openfhe import TOY
           security_level = TOY
        except ImportError:
           from openfhe import STD128
           security_level = STD128

        self.secret_key = self.scheme.generate_keys(security_level=security_level)

    def test_encrypt_decrypt(self):
        val = 1
        ct = self.scheme.encrypt(val, self.secret_key)
        decrypted = self.scheme.decrypt(ct, self.secret_key)
        self.assertEqual(val, decrypted)

        val = 0
        ct = self.scheme.encrypt(val, self.secret_key)
        decrypted = self.scheme.decrypt(ct, self.secret_key)
        self.assertEqual(val, decrypted)

    def test_gates(self):
        # Truth table verification
        # Helper to get fresh encryptions
        def get_cts(val1, val2):
            return self.scheme.encrypt(val1, self.secret_key), self.scheme.encrypt(val2, self.secret_key)

        # AND
        c1, c2 = get_cts(0, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_and(c1, c2), self.secret_key), 0)
        c1, c2 = get_cts(0, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_and(c1, c2), self.secret_key), 0)
        c1, c2 = get_cts(1, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_and(c1, c2), self.secret_key), 0)
        c1, c2 = get_cts(1, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_and(c1, c2), self.secret_key), 1)

        # OR
        c1, c2 = get_cts(0, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_or(c1, c2), self.secret_key), 0)
        c1, c2 = get_cts(0, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_or(c1, c2), self.secret_key), 1)
        c1, c2 = get_cts(1, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_or(c1, c2), self.secret_key), 1)
        c1, c2 = get_cts(1, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_or(c1, c2), self.secret_key), 1)

        # XOR
        c1, c2 = get_cts(0, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_xor(c1, c2), self.secret_key), 0)
        c1, c2 = get_cts(0, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_xor(c1, c2), self.secret_key), 1)
        c1, c2 = get_cts(1, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_xor(c1, c2), self.secret_key), 1)
        c1, c2 = get_cts(1, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_xor(c1, c2), self.secret_key), 0)

        # NAND
        c1, c2 = get_cts(0, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_nand(c1, c2), self.secret_key), 1)
        c1, c2 = get_cts(0, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_nand(c1, c2), self.secret_key), 1)
        c1, c2 = get_cts(1, 0)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_nand(c1, c2), self.secret_key), 1)
        c1, c2 = get_cts(1, 1)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_nand(c1, c2), self.secret_key), 0)
        
        # NOT
        ct0 = self.scheme.encrypt(0, self.secret_key)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_not(ct0), self.secret_key), 1)
        ct1 = self.scheme.encrypt(1, self.secret_key)
        self.assertEqual(self.scheme.decrypt(self.scheme.eval_not(ct1), self.secret_key), 0)

if __name__ == '__main__':
    unittest.main()
