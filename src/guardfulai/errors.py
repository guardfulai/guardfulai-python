"""Stable, content-free SDK error types."""

from dataclasses import dataclass


class GuardfulAIError(Exception):
    """Base class for SDK failures."""


class ConfigurationError(GuardfulAIError):
    """The local client configuration is unsafe or invalid."""


class ProtocolError(GuardfulAIError):
    """The server response did not match the documented contract."""


class TransportError(GuardfulAIError):
    """The request could not reach a conforming server after bounded retries."""


@dataclass(frozen=True)
class ErrorDetail:
    status_code: int
    code: str
    retryable: bool


class APIError(GuardfulAIError):
    def __init__(self, detail: ErrorDetail):
        self.detail = detail
        super().__init__(f"Guardful AI API error {detail.status_code}: {detail.code}")

    @property
    def status_code(self) -> int:
        return self.detail.status_code

    @property
    def code(self) -> str:
        return self.detail.code

    @property
    def retryable(self) -> bool:
        return self.detail.retryable


class AuthenticationError(APIError):
    pass


class PermissionDeniedError(APIError):
    pass


class PaymentRequiredError(APIError):
    pass


class NotFoundError(APIError):
    pass


class ConflictError(APIError):
    pass


class RateLimitError(APIError):
    pass


class ServiceUnavailableError(APIError):
    pass


ERROR_TYPES = {
    401: AuthenticationError,
    402: PaymentRequiredError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    429: RateLimitError,
    503: ServiceUnavailableError,
    504: ServiceUnavailableError,
}
