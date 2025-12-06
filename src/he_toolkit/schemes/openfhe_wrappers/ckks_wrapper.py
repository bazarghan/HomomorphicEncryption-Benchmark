from typing import Tuple, Any, List
from openfhe import *

class CKKSScheme:
    """
    Wrapper for OpenFHE CKKS Scheme.
    """

    def __init__(self):
        self.crypto_context = None
        self.key_pair = None

    def generate_keys(self, mult_depth: int = 3, scale_mod_size: int = 50, batch_size: int = 8) -> Tuple[Any, Any]:
        """
        Generates keys and sets up the CryptoContext.
        
        Args:
            mult_depth (int): Multiplicative depth.
            scale_mod_size (int): Size of the scaling modulus.
            batch_size (int): Size of the batch (slots).
            
        Returns:
            Tuple[Any, Any]: (public_key, private_key)
        """
        parameters = CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(mult_depth)
        parameters.SetScalingModSize(scale_mod_size)
        parameters.SetBatchSize(batch_size)
        
        self.crypto_context = GenCryptoContext(parameters)
        self.crypto_context.Enable(PKESchemeFeature.PKE)
        self.crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
        self.crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)
        
        self.key_pair = self.crypto_context.KeyGen()
        self.crypto_context.EvalMultKeyGen(self.key_pair.secretKey)
        
        # Generate rotation keys for summation if needed, but basic interface might not need it yet.
        # For now, we enable basic rotation just in case.
        self.crypto_context.EvalRotateKeyGen(self.key_pair.secretKey, [1, -1, 2, -2])

        return self.key_pair.publicKey, self.key_pair.secretKey

    def encrypt(self, plaintext_list: List[float], public_key: Any) -> Any:
        """
        Encrypts a list of floats.
        
        Args:
            plaintext_list (List[float]): List of values to encrypt.
            public_key (Any): The public key.
            
        Returns:
            Any: The encrypted ciphertext.
        """
        if self.crypto_context is None:
            raise RuntimeError("CryptoContext not initialized. Call generate_keys first.")
            
        plaintext = self.crypto_context.MakeCKKSPackedPlaintext(plaintext_list)
        ciphertext = self.crypto_context.Encrypt(public_key, plaintext)
        return ciphertext

    def decrypt(self, ciphertext: Any, private_key: Any) -> List[float]:
        """
        Decrypts a ciphertext to a list of floats.
        
        Args:
            ciphertext (Any): The ciphertext.
            private_key (Any): The private key.
            
        Returns:
            List[float]: The decrypted values.
        """
        if self.crypto_context is None:
            raise RuntimeError("CryptoContext not initialized. Call generate_keys first.")
            
        plaintext_result = self.crypto_context.Decrypt(ciphertext, private_key)
        # Set length to get the actual values we care about, 
        # but OpenFHE returns the full vector. 
        # We assume the user knows the batch size or we return everything.
        # Let's return the real part of the packed plaintext.
        return plaintext_result.GetRealPackedValue()

    def add(self, ciphertext1: Any, ciphertext2: Any) -> Any:
        """
        Homomorphically adds two ciphertexts.
        """
        return self.crypto_context.EvalAdd(ciphertext1, ciphertext2)

    def multiply(self, ciphertext1: Any, ciphertext2: Any) -> Any:
        """
        Homomorphically multiplies two ciphertexts.
        """
        return self.crypto_context.EvalMult(ciphertext1, ciphertext2)

    def multiply_scalar(self, ciphertext: Any, scalar: float) -> Any:
        """
        Homomorphically multiplies a ciphertext by a scalar.
        """
        return self.crypto_context.EvalMult(ciphertext, scalar)
