from typing import Any
from openfhe import *

class TFHEScheme:
    """
    Wrapper for OpenFHE BinFHE Scheme (TFHE).
    """

    def __init__(self):
        self.binfhe_context = BinFHEContext()
        self.secret_key = None
        # Public key is generally not used explicitly in BinFHE encryption in OpenFHE 
        # (it often uses symmetric encryption for fresh ciphertexts, though public key encryption is possible).
        # We will follow standard BinFHE usage.
        
    def generate_keys(self, security_level=STD128):
        """
        Generates keys and sets up the BinFHEContext.
        
        Args:
            security_level: Security level (default STD128).
        """
        self.binfhe_context.GenerateBinFHEContext(security_level)
        self.secret_key = self.binfhe_context.KeyGen()
        self.binfhe_context.BTKeyGen(self.secret_key)
        
        return self.secret_key

    def encrypt(self, value: int, secret_key: Any) -> Any:
        """
        Encrypts a bit (0 or 1).
        
        Args:
            value (int): 0 or 1.
            secret_key (Any): The secret key.
            
        Returns:
            Any: The encrypted ciphertext.
        """
        # BinFHE usually encrypts using secret key
        return self.binfhe_context.Encrypt(secret_key, value % 2)

    def decrypt(self, ciphertext: Any, secret_key: Any) -> int:
        """
        Decrypts a ciphertext to a bit.
        
        Args:
            ciphertext (Any): The ciphertext.
            secret_key (Any): The secret key.
            
        Returns:
            int: The decrypted bit (0 or 1).
        """
        return self.binfhe_context.Decrypt(secret_key, ciphertext)

    def eval_nand(self, ct1: Any, ct2: Any) -> Any:
        return self.binfhe_context.EvalBinGate(NAND, ct1, ct2)

    def eval_and(self, ct1: Any, ct2: Any) -> Any:
        return self.binfhe_context.EvalBinGate(AND, ct1, ct2)

    def eval_or(self, ct1: Any, ct2: Any) -> Any:
        return self.binfhe_context.EvalBinGate(OR, ct1, ct2)

    def eval_xor(self, ct1: Any, ct2: Any) -> Any:
        return self.binfhe_context.EvalBinGate(XOR, ct1, ct2)
        
    def eval_not(self, ct: Any) -> Any:
        # NOT is usually XOR with 1 or specific EvalNOT
        return self.binfhe_context.EvalNOT(ct)
