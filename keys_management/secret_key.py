from typing import Union, Tuple, Dict
from .consts import ENCRYPTION_KEY_TYPE, DECRYPTION_KEY_TYPE, PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE

SecretKeyValue = Union[str, bytes]
SecretKeyPairValues = Union[SecretKeyValue, Tuple[SecretKeyValue, SecretKeyValue], Dict[str, SecretKeyValue]]


class SecretKey:
    def __init__(self, secret_key_value: SecretKeyValue):
        self._val = secret_key_value

    def get_value(self):
        return self._val


class SecretKeyDefinition:
    name: str


class SecretKeyPair:
    _decrypt_key: SecretKey
    _encrypt_key: SecretKey

    def __init__(self, secret_key_pair_values: SecretKeyPairValues):
        encrypt_key, decrypt_key = None, None
        if isinstance(secret_key_pair_values, (str, bytes)):
            encrypt_key = secret_key_pair_values
            decrypt_key = secret_key_pair_values
        elif isinstance(secret_key_pair_values, dict):
            encrypt_key = secret_key_pair_values[
                ENCRYPTION_KEY_TYPE] if ENCRYPTION_KEY_TYPE in secret_key_pair_values else secret_key_pair_values.get(
                PUBLIC_KEY_TYPE, None)
            decrypt_key = secret_key_pair_values[
                DECRYPTION_KEY_TYPE] if DECRYPTION_KEY_TYPE in secret_key_pair_values else secret_key_pair_values.get(
                PRIVATE_KEY_TYPE, None)
        elif isinstance(secret_key_pair_values, tuple):
            encrypt_key, decrypt_key = secret_key_pair_values
        self._encrypt_key = SecretKey(encrypt_key)
        self._decrypt_key = SecretKey(decrypt_key)

    def is_symmetric(self) -> bool:
        return self._decrypt_key == self._encrypt_key

    def is_asymmetric(self) -> bool:
        return self._decrypt_key != self._encrypt_key

    @property
    def decrypt_key(self) -> SecretKey:
        return self._decrypt_key

    @property
    def encrypt_key(self) -> SecretKey:
        return self._encrypt_key
