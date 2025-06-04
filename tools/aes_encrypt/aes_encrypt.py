import base64
import os
from collections.abc import Generator
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage


class AesEncryptTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage]:
        plaintext: str = tool_parameters.get("plaintext")
        if not plaintext or not isinstance(plaintext, str):
            raise ValueError("Not a valid file for input input_file")

        key_text: str = tool_parameters.get("key_text")
        if not key_text or not isinstance(key_text, str):
            raise ValueError("Encryption key is required")
        key_bytes: bytes = base64.b64decode(key_text.encode())
        if len(key_bytes) not in [128, 192, 256]:
            raise ValueError("Invalid decoded AES key length, which must be either 128, 192, or 256 bits")

        try:
            salt_bytes, encrypted_bytes = self.encrypt_data(key=key_bytes, data=plaintext.encode())
            result_base64_str = base64.urlsafe_b64encode(salt_bytes + encrypted_bytes).decode()
            yield self.create_text_message(result_base64_str)
        except ValueError as e:
            raise ValueError("Failed to encrypt data") from e

    @staticmethod
    def encrypt_data(key: bytes, data: bytes) -> (bytes, bytes):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext
