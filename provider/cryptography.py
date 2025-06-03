from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError

from tools.md5sum.md5sum import Md5SumTool
from tools.rsa_decrypt.rsa_decrypt import RsaDecryptTool
from tools.rsa_encrypt.rsa_encrypt import RsaEncryptTool
from tools.rsa_keygen.rsa_keygen import RsaKeygenTool
from tools.sha256sum.sha256sum import Sha256SumTool


class CryptoProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        try:
            """
            IMPLEMENT YOUR VALIDATION HERE
            """
            Sha256SumTool.from_credentials({})
            Md5SumTool.from_credentials({})
            RsaKeygenTool.from_credentials({})
            RsaEncryptTool.from_credentials({})
            RsaDecryptTool.from_credentials({})
        except Exception as e:
            raise ToolProviderCredentialValidationError(str(e))
