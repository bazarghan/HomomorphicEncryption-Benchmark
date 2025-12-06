from typing import Tuple, Any, Dict
import gmpy2
from gmpy2 import mpz
from he_toolkit.interfaces import HEScheme

class ElGamalScheme(HEScheme):
    """
    Implementation of the Standard ElGamal Homomorphic Encryption Scheme using gmpy2.
    This scheme supports MULTIPLICATIVE homomorphism.
    
    Properties:
    - Enc(m1) * Enc(m2) = Enc(m1 * m2)
    - Decryption works for any size plaintext (no DLP required).
    - Additive homomorphism is NOT supported.
    """

    def generate_keys(self, key_size: int = 2048) -> Tuple[Any, Any]:
        """
        Generates a public/private key pair.
        
        Args:
            key_size (int): The size of the prime p in bits.
            
        Returns:
            Tuple[Any, Any]: (public_key, private_key)
                public_key = (p, g, h) where h = g^x mod p
                private_key = (p, x)
        """
        rs = gmpy2.random_state()
        
        # Generate prime p
        p = gmpy2.next_prime(gmpy2.mpz_urandomb(rs, key_size))
        
        # Generate generator g
        g = gmpy2.mpz_urandomb(rs, key_size) % p
        while g <= 1:
             g = gmpy2.mpz_urandomb(rs, key_size) % p

        # Generate private key x
        x = gmpy2.mpz_urandomb(rs, key_size - 1) % (p - 1)
        while x <= 1:
            x = gmpy2.mpz_urandomb(rs, key_size - 1) % (p - 1)

        # Compute public parameter h = g^x mod p
        h = gmpy2.powmod(g, x, p)

        public_key = (p, g, h)
        private_key = (p, x)
        
        return public_key, private_key

    def encrypt(self, plaintext: float, public_key: Any) -> Dict[str, Any]:
        """
        Encrypts a plaintext value using Standard ElGamal.
        c = (c1, c2) = (g^r, m * h^r)
        
        Args:
            plaintext (float): The value to encrypt. Must be an integer.
            public_key (Any): The public key (p, g, h).
            
        Returns:
            Dict[str, Any]: The encrypted ciphertext {'c1': c1, 'c2': c2, 'p': p}.
        """
        p, g, h = public_key
        m = int(plaintext)
        
        rs = gmpy2.random_state()
        r = gmpy2.mpz_urandomb(rs, p.bit_length() - 1) % (p - 1)
        
        # c1 = g^r
        c1 = gmpy2.powmod(g, r, p)
        
        # s = h^r
        s = gmpy2.powmod(h, r, p)
        
        # c2 = m * s mod p
        c2 = gmpy2.mul(m, s) % p
        
        return {'c1': c1, 'c2': c2, 'p': p}

    def decrypt(self, ciphertext: Dict[str, Any], private_key: Any) -> float:
        """
        Decrypts a ciphertext value using Standard ElGamal decryption.
        m = c2 * (c1^x)^(-1) mod p
        
        Args:
            ciphertext (Dict[str, Any]): The ciphertext {'c1': c1, 'c2': c2, 'p': p}.
            private_key (Any): The private key (p, x).
            
        Returns:
            float: The decrypted plaintext.
        """
        p, x = private_key
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        
        # s = c1^x
        s = gmpy2.powmod(c1, x, p)
        
        # s_inv = s^(-1) mod p
        s_inv = gmpy2.invert(s, p)
        
        # m = c2 * s_inv mod p
        m = gmpy2.mul(c2, s_inv) % p
        
        return float(m)

    def add(self, ciphertext1: Dict[str, Any], ciphertext2: Dict[str, Any]) -> Any:
        """
        Standard ElGamal does NOT support additive homomorphism.
        """
        raise NotImplementedError("Standard ElGamal does not support homomorphic addition.")

    def multiply_scalar(self, ciphertext: Dict[str, Any], scalar: float) -> Any:
        """
        Standard ElGamal does NOT support scalar multiplication in the additive sense.
        (It supports exponentiation for plaintext exponentiation, but that's not the standard scalar mult interface).
        """
        raise NotImplementedError("Standard ElGamal does not support homomorphic scalar multiplication.")

    def multiply(self, ciphertext1: Dict[str, Any], ciphertext2: Dict[str, Any]) -> Dict[str, Any]:
        """
        Homomorphically multiplies two ciphertexts.
        Enc(m1) * Enc(m2) = (g^r1, m1 h^r1) * (g^r2, m2 h^r2)
                          = (g^(r1+r2), (m1 m2) h^(r1+r2))
                          = Enc(m1 * m2)
        
        Args:
            ciphertext1 (Dict[str, Any]): The first ciphertext.
            ciphertext2 (Dict[str, Any]): The second ciphertext.
            
        Returns:
            Dict[str, Any]: The result of the multiplication.
        """
        p = ciphertext1['p']
        if p != ciphertext2['p']:
            raise ValueError("Ciphertexts must be from the same key (same modulus p)")
            
        c1_new = gmpy2.mul(ciphertext1['c1'], ciphertext2['c1']) % p
        c2_new = gmpy2.mul(ciphertext1['c2'], ciphertext2['c2']) % p
        
        return {'c1': c1_new, 'c2': c2_new, 'p': p}
