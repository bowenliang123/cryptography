import base64
from collections.abc import Generator
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage


class AesDecryptTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage]:
        ciphertext: str = tool_parameters.get("ciphertext")
        if not ciphertext or not isinstance(ciphertext, str):
            raise ValueError("Not a valid file for input input_file")

        key_text: str = tool_parameters.get("key_text")
        if not key_text or not isinstance(key_text, str):
            raise ValueError("Encryption key is required")
        key_bytes: bytes = base64.b64decode(key_text.encode())
        if len(key_bytes) not in [128, 192, 256]:
            raise ValueError("Invalid decoded AES key length, which must be either 128, 192, or 256 bits")

        try:
            decrypted_bytes = self.decrypt_data(key=key_bytes,
                                                encrypted_data=base64.b64decode(ciphertext.encode("utf-8")))
            result_str = decrypted_bytes.decode("utf-8")
            yield self.create_text_message(result_str)
        except ValueError as e:
            raise ValueError("Failed to decrypt data") from e

    @staticmethod
    def decrypt_data(key: bytes, encrypted_data: bytes) -> bytes:
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return decrypted_data
