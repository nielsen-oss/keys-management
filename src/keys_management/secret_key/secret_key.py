from __future__ import annotations
from math import floor
from typing import TYPE_CHECKING, Any, Optional, Union
from .errors import InitError

if TYPE_CHECKING:
    from .types import SecretKeyPairValues, SecretKeyValue


class SecretKey:
    _val: SecretKeyValue

    def __init__(self, secret_key_value: SecretKeyValue):
        if isinstance(secret_key_value, (str, bytes)):
            self._val = secret_key_value
        else:
            raise SecretKeyInitError(secret_key_value)

    def __str__(self) -> str:
        return self.censor_key()

    def get_value(self) -> SecretKeyValue:
        return self._val

    def censor_key(self) -> str:
        """
        censorString('') = ''; censorString('a') = '*'; censorString('aa') = '**';
        censorString('aaa') = '***'; censorString('aaaa') = 'a**a'; censorString('aaaaa') = 'a***a';
        censorString('aaaaaaa') = 'a****a'; censorString('aaaaaaa') = 'a*****a';
        censorString('aaaaaaaa') = 'aa****aa';
        """
        str_to_censor = str(self._val)
        key_length = len(str_to_censor)

        revealedPartSize = min(4, floor(key_length / 4))
        return (
            str_to_censor[0:revealedPartSize]
            + "*" * (key_length - 2 * revealedPartSize)
            + str_to_censor[key_length - revealedPartSize :]
        )


class SecretKeyInitError(InitError):
    def __init__(self, secret_key_value: Any) -> None:
        super().__init__(
            "SecretKey",
            "secret_key_value type is %s" % str(type(secret_key_value)),
        )


class SecretKeyPair:
    _decrypt_key: SecretKey
    _encrypt_key: SecretKey
    _is_symmetric: bool

    def __init__(self, value_or_values: Union[SecretKeyValue, SecretKeyPairValues]):
        encrypt_key: SecretKeyValue
        decrypt_key: SecretKeyValue
        if isinstance(value_or_values, (str, bytes)):
            encrypt_key = value_or_values
            decrypt_key = value_or_values
        elif isinstance(value_or_values, tuple) and len(value_or_values) == 2:
            encrypt_key, decrypt_key = value_or_values
        else:
            raise SecretKeyPairInitError(value_or_values)
        self._encrypt_key = SecretKey(encrypt_key)
        self._decrypt_key = SecretKey(decrypt_key)
        self._is_symmetric = encrypt_key == decrypt_key

    def __str__(self) -> str:
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


class SecretKeyFactory:
    @staticmethod
    def create(
        value_or_values: Optional[Union[SecretKeyValue, SecretKeyPairValues]]
    ) -> Optional[Union[SecretKey, SecretKeyPair]]:
        if value_or_values is None:
            return None
        if isinstance(value_or_values, (str, bytes)):
            return SecretKey(value_or_values)
        elif isinstance(value_or_values, tuple):
            return SecretKeyPair(value_or_values)
        raise SecretKeyPairInitError(value_or_values)

    def __call__(
        self, value_or_values: Union[SecretKeyValue, SecretKeyPairValues]
    ) -> Optional[Union[SecretKey, SecretKeyPair]]:
        return self.create(value_or_values)


class SecretKeyPairInitError(InitError):
    def __init__(self, secret_key_pair_values: Any) -> None:
        super().__init__(
            "SecretKeyPair",
            "secret_key_pair_values type is %s" % str(type(secret_key_pair_values)),
        )
