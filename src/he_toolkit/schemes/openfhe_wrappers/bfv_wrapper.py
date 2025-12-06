from typing import Tuple, Any, List
from openfhe import *

class BFVScheme:
    """
    Wrapper for OpenFHE BFV Scheme.
    """

    def __init__(self):
        self.crypto_context = None
        self.key_pair = None
        self.batch_size = 0

    def generate_keys(self, plain_modulus: int = 65537, mult_depth: int = 2, scale_mod_size: int = 50, batch_size: int = 8) -> Tuple[Any, Any]:
        """
        Generates keys and sets up the CryptoContext.
        
        Args:
            plain_modulus (int): Plaintext modulus.
            mult_depth (int): Multiplicative depth.
            scale_mod_size (int): Size of the scaling modulus.
            batch_size (int): Size of the batch (slots).
            
        Returns:
            Tuple[Any, Any]: (public_key, private_key)
        """
        self.batch_size = batch_size
        parameters = CCParamsBFVRNS()
        parameters.SetPlaintextModulus(plain_modulus)
        parameters.SetMultiplicativeDepth(mult_depth)
        parameters.SetScalingModSize(scale_mod_size)
        parameters.SetBatchSize(batch_size)
        
        self.crypto_context = GenCryptoContext(parameters)
        self.crypto_context.Enable(PKESchemeFeature.PKE)
        self.crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
        self.crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)
        self.crypto_context.Enable(PKESchemeFeature.ADVANCEDSHE)
        
        self.key_pair = self.crypto_context.KeyGen()
        self.crypto_context.EvalMultKeyGen(self.key_pair.secretKey)
        
        # Generate rotation keys for potential future use
        self.crypto_context.EvalRotateKeyGen(self.key_pair.secretKey, [1, -1, 2, -2])

        return self.key_pair.publicKey, self.key_pair.secretKey

    def encrypt(self, plaintext_list: List[int], public_key: Any) -> Any:
        """
        Encrypts a list of integers.
        
        Args:
            plaintext_list (List[int]): List of values to encrypt.
            public_key (Any): The public key.
            
        Returns:
            Any: The encrypted ciphertext.
        """
        if self.crypto_context is None:
            raise RuntimeError("CryptoContext not initialized. Call generate_keys first.")
            
        plaintext = self.crypto_context.MakePackedPlaintext(plaintext_list)
        ciphertext = self.crypto_context.Encrypt(public_key, plaintext)
        return ciphertext

    def decrypt(self, ciphertext: Any, private_key: Any) -> List[int]:
        """
        Decrypts a ciphertext to a list of integers.
        
        Args:
            ciphertext (Any): The ciphertext.
            private_key (Any): The private key.
            
        Returns:
            List[int]: The decrypted values.
        """
        if self.crypto_context is None:
            raise RuntimeError("CryptoContext not initialized. Call generate_keys first.")
            
        plaintext_result = self.crypto_context.Decrypt(ciphertext, private_key)
        return plaintext_result.GetPackedValue()

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

    def multiply_scalar(self, ciphertext: Any, scalar: int) -> Any:
        """
        Homomorphically multiplies a ciphertext by a scalar.
        """
        if self.crypto_context is None:
             raise RuntimeError("CryptoContext not initialized. Call generate_keys first.")

        scalar_vec = [scalar] * self.batch_size
        scalar_pt = self.crypto_context.MakePackedPlaintext(scalar_vec)
        
        return self.crypto_context.EvalMult(ciphertext, scalar_pt)
