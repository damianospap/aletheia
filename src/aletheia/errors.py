"""Exception hierarchy.

Every error carries:

* a stable machine ``code`` (safe to match on in scripts and logs),
* an i18n ``key`` plus parameters, so the CLI can print it in the user's language,
* a process ``exit_code`` (loosely following sysexits.h),
* a ``retryable`` flag for callers that implement retry logic.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

EXIT_OK = 0


class AletheiaError(Exception):
    """Base class for all expected, user-facing errors."""

    code = "E_GENERIC"
    key = "error.generic"
    exit_code = 1
    retryable = False

    def __init__(self, detail: str = "", *, key: str | None = None, code: str | None = None, **params: Any) -> None:
        super().__init__(detail or key or self.key)
        if key is not None:
            self.key = key
        if code is not None:
            self.code = code
        self.detail = detail
        self.params: dict[str, Any] = {"detail": detail, **params}

    def localized(self, translate: Callable[..., str]) -> str:
        """Render the error with the given translator (``Translator.__call__``)."""
        return translate(self.key, **self.params)


# --- usage / validation ----------------------------------------------------------------------


class UsageError(AletheiaError):
    code = "E_USAGE"
    key = "error.usage"
    exit_code = 2


class InvalidCaseIdError(UsageError):
    code = "E_BAD_CASE_ID"
    key = "error.vault.bad_id"


class OutputExistsError(UsageError):
    code = "E_OUT_EXISTS"
    key = "error.out_exists"


class ValidationError(AletheiaError):
    code = "E_VALIDATION"
    key = "error.validation"
    exit_code = 3


class InputTooLargeError(ValidationError):
    code = "E_INPUT_TOO_LARGE"
    key = "error.input_too_large"


class ParseError(AletheiaError):
    code = "E_PARSE"
    key = "error.export.format"
    exit_code = 3


class UnsafeArchiveError(ParseError):
    code = "E_UNSAFE_ARCHIVE"
    key = "error.export.unsafe_archive"


class PackError(ParseError):
    code = "E_PACK"
    key = "error.pack.invalid"


# --- vault -----------------------------------------------------------------------------------


class VaultError(AletheiaError):
    code = "E_VAULT"
    exit_code = 4


class CaseNotFoundError(VaultError):
    code = "E_CASE_NOT_FOUND"
    key = "error.vault.not_found"


class VaultLockedError(VaultError):
    code = "E_VAULT_LOCKED"
    key = "error.vault.locked"
    retryable = True


class VaultIntegrityError(VaultError):
    code = "E_VAULT_CORRUPT"
    key = "error.vault.corrupt"


class VaultTooNewError(VaultError):
    code = "E_VAULT_TOO_NEW"
    key = "error.vault.too_new"


class UnsafeStorageError(VaultError):
    code = "E_STORAGE_UNSAFE"
    key = "error.storage.shared"


# --- policy ----------------------------------------------------------------------------------


class PolicyError(AletheiaError):
    code = "E_POLICY"
    exit_code = 77


class AupNotAcceptedError(PolicyError):
    code = "E_AUP_REQUIRED"
    key = "error.policy.aup_required"


class ActiveConfirmationRequired(PolicyError):
    code = "E_ACTIVE_CONFIRM"
    key = "error.policy.active_confirm"


class RobotsDisallowedError(PolicyError):
    code = "E_ROBOTS"
    key = "error.policy.robots"


# --- network ---------------------------------------------------------------------------------


class NetworkError(AletheiaError):
    code = "E_NET"
    key = "error.net.transport"
    exit_code = 5


class TransportError(NetworkError):
    code = "E_NET_TRANSPORT"
    retryable = True


class TlsError(NetworkError):
    code = "E_NET_TLS"
    key = "error.net.tls"


class BlockedTargetError(NetworkError):
    code = "E_NET_BLOCKED"
    key = "error.net.blocked"


class ResponseTooLargeError(NetworkError):
    code = "E_NET_TOO_LARGE"
    key = "error.net.too_large"


class TooManyRedirectsError(NetworkError):
    code = "E_NET_REDIRECTS"
    key = "error.net.redirects"


class NoRdapServiceError(NetworkError):
    code = "E_NO_RDAP"
    key = "error.rdap.no_service"


# --- internal --------------------------------------------------------------------------------


class InternalError(AletheiaError):
    code = "E_INTERNAL"
    key = "error.internal"
    exit_code = 70


class HttpStatusError(NetworkError):
    code = "E_NET_STATUS"
    key = "error.net.status"
