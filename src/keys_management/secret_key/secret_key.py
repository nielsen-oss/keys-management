from __future__ import annotations
from math import floor
from typing import TYPE_CHECKING, Any, Optional, Union
from .errors import InitError, SecretKeyInitError, SecretKeyPairInitError

if TYPE_CHECKING:
    from .types import StrOrBytes, StrOrBytesPair


class SecretKeyValue:
    _val: StrOrBytes

    def __init__(self, secret_key_value: StrOrBytes):
        if isinstance(secret_key_value, (str, bytes)):
            self._val = secret_key_value
        else:
            raise SecretKeyInitError(secret_key_value)

    def __str__(self) -> str:
        return self.censor_key()

    def get_value(self) -> StrOrBytes:
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


class SecretKeyPair:
    _forward_path_key: SecretKeyValue
    _back_path_key: SecretKeyValue
    _is_symmetric: bool

    def __init__(self, value_or_values: Union[StrOrBytes, StrOrBytesPair]):
        forward_path_key: StrOrBytes
        back_path_key: StrOrBytes
        if isinstance(value_or_values, (str, bytes)):
            forward_path_key = value_or_values
            back_path_key = value_or_values
        elif isinstance(value_or_values, tuple) and len(value_or_values) == 2:
            forward_path_key, back_path_key = value_or_values
        else:
            raise SecretKeyPairInitError(value_or_values)
        self._forward_path_key = SecretKeyValue(forward_path_key)
        self._back_path_key = SecretKeyValue(back_path_key)
        self._is_symmetric = forward_path_key == back_path_key

    def __str__(self) -> str:
        if self.is_symmetric():
            return '"%s"' % str(self._back_path_key)
        else:
            return 'encrypt: "{}", decrypt: "{}"'.format(
                str(self._forward_path_key), str(self._back_path_key)
            )

    def is_symmetric(self) -> bool:
        return self._is_symmetric

    def is_asymmetric(self) -> bool:
        return not self._is_symmetric

    @property
    def back_path_key(self) -> SecretKeyValue:
        return self._back_path_key

    @property
    def forward_key(self) -> SecretKeyValue:
        return self._forward_path_key


class SecretKeyFactory:
    @staticmethod
    def create(
        value_or_values: Optional[Union[StrOrBytes, StrOrBytesPair]]
    ) -> Optional[Union[SecretKeyValue, SecretKeyPair]]:
        if value_or_values is None:
            return None
        if isinstance(value_or_values, (str, bytes)):
            return SecretKeyValue(value_or_values)
        elif isinstance(value_or_values, tuple):
            return SecretKeyPair(value_or_values)
        raise SecretKeyPairInitError(value_or_values)

    def __call__(
        self, value_or_values: Union[StrOrBytes, StrOrBytesPair]
    ) -> Optional[Union[SecretKeyValue, SecretKeyPair]]:
        return self.create(value_or_values)
