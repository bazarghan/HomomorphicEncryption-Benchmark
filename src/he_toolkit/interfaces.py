from abc import ABC, abstractmethod
from typing import Any, Tuple

class HEScheme(ABC):
    """
    Abstract Base Class for Homomorphic Encryption Schemes.
    """

    @abstractmethod
    def generate_keys(self, key_size: int = 2048) -> Tuple[Any, Any]:
        """
        Generates a public/private key pair.
        
        Args:
            key_size (int): The size of the key in bits.
            
        Returns:
            Tuple[Any, Any]: (public_key, private_key)
        """
        pass

    @abstractmethod
    def encrypt(self, plaintext: float, public_key: Any) -> Any:
        """
        Encrypts a plaintext value.
        
        Args:
            plaintext (float): The value to encrypt.
            public_key (Any): The public key to use for encryption.
            
        Returns:
            Any: The encrypted ciphertext.
        """
        pass

    @abstractmethod
    def decrypt(self, ciphertext: Any, private_key: Any) -> float:
        """
        Decrypts a ciphertext value.
        
        Args:
            ciphertext (Any): The ciphertext to decrypt.
            private_key (Any): The private key to use for decryption.
            
        Returns:
            float: The decrypted plaintext.
        """
        pass

    @abstractmethod
    def add(self, ciphertext1: Any, ciphertext2: Any) -> Any:
        """
        Homomorphically adds two ciphertexts.
        
        Args:
            ciphertext1 (Any): The first ciphertext.
            ciphertext2 (Any): The second ciphertext.
            
        Returns:
            Any: The result of the addition (Enc(m1 + m2)).
        """
        pass

    @abstractmethod
    def multiply_scalar(self, ciphertext: Any, scalar: float) -> Any:
        """
        Homomorphically multiplies a ciphertext by a scalar.
        
        Args:
            ciphertext (Any): The ciphertext.
            scalar (float): The scalar value.
            
        Returns:
            Any: The result of the multiplication (Enc(m * scalar)).
        """
        pass
