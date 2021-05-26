from __future__ import annotations
from typing import TYPE_CHECKING, Any
from math import floor

from .errors import InitError
from ..consts import (
    ENCRYPTION_KEY_TYPE,
    PUBLIC_KEY_TYPE,
    PRIVATE_KEY_TYPE,
    DECRYPTION_KEY_TYPE,
)

if TYPE_CHECKING:
    from .types import SecretKeyValue, SecretKeyPairValues


class SecretKey:
    def __init__(self, secret_key_value: SecretKeyValue):
        if isinstance(secret_key_value, (str, tuple)):
            self._val = secret_key_value
        else:
            raise SecretKeyInitError(secret_key_value)

    def __str__(self):
        return self.censor_key()

    def get_value(self) -> SecretKeyValue:
        return self._val

    def censor_key(self):
        """
        censorString('') = ''; censorString('a') = '*'; censorString('aa') = '**';
        censorString('aaa') = '***'; censorString('aaaa') = 'a**a'; censorString('aaaaa') = 'a***a';
        censorString('aaaaaaa') = 'a****a'; censorString('aaaaaaa') = 'a*****a';
        censorString('aaaaaaaa') = 'aa****aa';
        """
        str_to_censor = self._val
        key_length = len(str_to_censor)

        revealedPartSize = min(4, floor(key_length / 4))
        return (
                str_to_censor[0:revealedPartSize]
                + "*" * (key_length - 2 * revealedPartSize)
                + str_to_censor[key_length - revealedPartSize:]
        )


class SecretKeyInitError(InitError):
    def __init__(self, secret_key_value: Any) -> None:
        super().__init__(
            'SecretKey',
            "secret_key_value type is %s" % str(type(secret_key_value)),
        )


class SecretKeyPair:
    _decrypt_key: SecretKey
    _encrypt_key: SecretKey
    _is_symmetric: bool

    def __init__(self, secret_key_pair_values: SecretKeyPairValues):
        if isinstance(secret_key_pair_values, (str, bytes)):
            encrypt_key = secret_key_pair_values
            decrypt_key = secret_key_pair_values
        elif isinstance(secret_key_pair_values, dict):
            encrypt_key = (
                secret_key_pair_values[ENCRYPTION_KEY_TYPE]
                if ENCRYPTION_KEY_TYPE in secret_key_pair_values
                else secret_key_pair_values.get(PUBLIC_KEY_TYPE, None)
            )
            decrypt_key = (
                secret_key_pair_values[DECRYPTION_KEY_TYPE]
                if DECRYPTION_KEY_TYPE in secret_key_pair_values
                else secret_key_pair_values.get(PRIVATE_KEY_TYPE, None)
            )
        elif isinstance(secret_key_pair_values, tuple):
            encrypt_key, decrypt_key = secret_key_pair_values
        else:
            raise SecretKeyPairInitError(secret_key_pair_values)
        self._encrypt_key = SecretKey(encrypt_key)
        self._decrypt_key = SecretKey(decrypt_key)
        self._is_symmetric = encrypt_key == decrypt_key

    def __str__(self):
        if self.is_symmetric():
            return '"%s"' % str(self._decrypt_key)
        else:
            return 'encrypt: "{}", decrypt: "{}"'.format(
                str(self._encrypt_key), str(self._decrypt_key)
            )

    def is_symmetric(self) -> bool:
        return self._is_symmetric

    def is_asymmetric(self) -> bool:
        return not self._is_symmetric

    @property
    def decrypt_key(self) -> SecretKey:
        return self._decrypt_key

    @property
    def encrypt_key(self) -> SecretKey:
        return self._encrypt_key


class SecretKeyPairInitError(InitError):
    def __init__(self, secret_key_pair_values: Any) -> None:
        super().__init__(
            'SecretKeyPair',
            "secret_key_pair_values type is %s"
            % str(type(secret_key_pair_values)),
        )
