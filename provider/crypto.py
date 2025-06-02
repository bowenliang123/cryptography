from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError

from tools.sha256sum.sha256sum_tool import Sha256SumTool


class CryptoProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        try:
            """
            IMPLEMENT YOUR VALIDATION HERE
            """
            Sha256SumTool.from_credentials({})
        except Exception as e:
            raise ToolProviderCredentialValidationError(str(e))
