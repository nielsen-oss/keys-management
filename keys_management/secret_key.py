from __future__ import annotations
from typing import TYPE_CHECKING, Union, Tuple, Dict, Callable, List
from math import floor
from enum import Enum
from abc import ABC, abstractmethod
from .consts import ENCRYPTION_KEY_TYPE, DECRYPTION_KEY_TYPE, PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE
from keys_management.consts import ENCRYPTED_STATE, DECRYPTED_STATE


if TYPE_CHECKING:
    from . import OnChange

SecretKeyValue = Union[str, bytes]
SecretKeyPairValues = Union[SecretKeyValue, Tuple[SecretKeyValue, SecretKeyValue], Dict[str, SecretKeyValue]]
KeysStore = Callable[[], SecretKeyPairValues]
ERROR_MSG = ""


class SecretKey:
    def __init__(self, secret_key_value: SecretKeyValue):
        if isinstance(secret_key_value, (str, tuple)):
            self._val = secret_key_value
        else:
            raise ValueError(ERROR_MSG)

    def __str__(self):
        return censorString(self._val)

    def get_value(self) -> SecretKeyValue:
        return self._val


def censorString(str_to_censor: str):
    '''
    censorString('') = ''; censorString('a') = '*'; censorString('aa') = '**';
    censorString('aaa') = '***'; censorString('aaaa') = 'a**a'; censorString('aaaaa') = 'a***a';
    censorString('aaaaaaa') = 'a****a'; censorString('aaaaaaa') = 'a*****a';
    censorString('aaaaaaaa') = 'aa****aa';
    '''

    strLength = len(str_to_censor)

    revealedPartSize = min(4, floor(strLength / 4))
    return str_to_censor[0: revealedPartSize] + "*" * (strLength - 2 * revealedPartSize) + str_to_censor[strLength - revealedPartSize:]


class SecretKeyPair:
    _decrypt_key: SecretKey
    _encrypt_key: SecretKey
    _is_symmetric: bool

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
        self._is_symmetric = encrypt_key == decrypt_key

    def __str__(self):
        if self.is_symmetric():
            return '"%s"' % str(self._decrypt_key)
        else:
            return 'encrypt: "{}", decrypt: "{}"'.format(str(self._encrypt_key), str(self._decrypt_key))

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


class SecretKeyUseCase(Enum):
    ENCRYPTION_DECRYPTION = 1
    ENCRYPTION = 2
    DECRYPTION = 3
    AUTHENTICATION = 4

    @staticmethod
    def get(str_val: str) -> SecretKeyUseCase:
        if str_val == ENCRYPTED_STATE:
            return SecretKeyUseCase.DECRYPTION
        if str_val == DECRYPTED_STATE:
            return SecretKeyUseCase.ENCRYPTION
        # TO DO raise error
        try:
            return SecretKeyUseCase[str_val.upper()]
        except KeyError:
            raise InvalidUseCaseName(str_val)


class InvalidUseCaseName(RuntimeError):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class SecretKeyState(ABC):
    @abstractmethod
    def get_last_use_case(self) -> SecretKeyUseCase:
        pass

    @abstractmethod
    def set_last_use_case(self, last_use: SecretKeyUseCase):
        pass

    @abstractmethod
    def get_previous_keys(self):
        pass

    @abstractmethod
    def set_previous_keys(self, keys: SecretKeyPairValues):
        pass

    @abstractmethod
    def clean_state(self) -> None:
        pass


class OnChangeKeyDefinition(SecretKeyState):
    __originalKeyDefinition: BaseSecretKeyDefinition
    __key_state: SecretKeyState

    def __init__(self, originalKeyDefinition: BaseSecretKeyDefinition):
        self.__originalKeyDefinition = originalKeyDefinition
        self.__state = originalKeyDefinition.get_key_state()

    @property
    def name(self) -> str:
        return self.__originalKeyDefinition.name

    @property
    def keys_store(self) -> KeysStore:
        return self.__originalKeyDefinition.keys_store

    def is_stateless(self) -> bool:
        return self.__originalKeyDefinition.is_stateless()

    def is_stated(self) -> bool:
        return not self.__originalKeyDefinition.is_stated()

    @property
    def use_case(self) -> SecretKeyUseCase:
        return self.__originalKeyDefinition.use_case

    def is_target_data_accessible(self) -> bool:
        return self.__originalKeyDefinition.is_target_data_accessible()

    def is_keep_in_cache(self) -> bool:
        return self.__originalKeyDefinition.is_keep_in_cache()

    def get_last_use_case(self) -> SecretKeyUseCase:
        return self.__state.get_last_use_case()

    def set_last_use_case(self, last_use: SecretKeyUseCase) -> None:
        self.__state.set_last_use_case(last_use)

    def get_previous_keys(self):
        return self.__state.get_previous_keys()

    def set_previous_keys(self, keys: SecretKeyPairValues) -> None:
        self.__state.set_previous_keys(keys)

    def clean_state(self) -> None:
        self.__state.clean_state()


class BaseSecretKeyDefinition(ABC):
    _name: str
    _store: KeysStore
    _use_case: SecretKeyUseCase
    _stateless: bool
    _target_data_accessible: bool
    _keep_in_cache: bool
    _on_change_callbacks: List[OnChange]

    def __init__(self, name: str, keys_store: KeysStore, **kwargs):
        self._name = name
        self._keys_store = keys_store
        self._use_case = kwargs.get('use_case', SecretKeyUseCase.ENCRYPTION_DECRYPTION)
        self._stateless = kwargs.get('stateless', True)
        self._target_data_accessible = kwargs.get('target_data_accessible', True)
        self._keep_in_cache = kwargs.get('keep_in_cache', True)
        self._on_change_callbacks = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def keys_store(self) -> KeysStore:
        return self._keys_store

    def is_stateless(self) -> bool:
        return self._stateless

    def is_stated(self) -> bool:
        return not self._stateless

    @property
    def use_case(self) -> SecretKeyUseCase:
        return self._use_case

    def is_target_data_accessible(self) -> bool:
        return self._target_data_accessible

    @property
    def on_change_callbacks(self) -> List[OnChange]:
        return self._on_change_callbacks

    def is_keep_in_cache(self) -> bool:
        return self._keep_in_cache

    @abstractmethod
    def get_key_state(self) -> SecretKeyState:
        pass

    @abstractmethod
    def set_key_state(self, key_state: SecretKeyState) -> None:
        pass
