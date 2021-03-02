from __future__ import annotations
from typing import Callable, Optional, Any, Union, Dict
from .secret_key import SecretKeyValue, SecretKeyPairValues


KeysStore = Callable[[], SecretKeyPairValues]
OnChange = Callable[[Union[SecretKeyPairValues], Union[SecretKeyPairValues]], None]


class KeysManagement(object):
    def define_key(self, key_name: str, keys_store: KeysStore, is_stateless: bool = True) -> KeysManagement:
        raise NotImplementedError()

    def get_key(self, key_name: str, is_for_encrypt: bool = None) -> SecretKeyValue:
        raise NotImplementedError()

    def key_changed(self, key_name: str, old_keys: SecretKeyPairValues, new_keys: SecretKeyPairValues, new_key_store: Optional[KeysStore] = None) -> None:
        raise NotImplementedError()

    def register_on_change(self, key_name: str, on_change_func: OnChange) -> None:
        raise NotImplementedError()


class StateRepoInterface(object):
    def write_state(self, key: str, key_state: Any) -> None:
        raise NotImplementedError()

    def read_state(self, key: str) -> Dict:
        raise NotImplementedError()


class CryptoTool(object):
    def encrypt(self, data: Any):
        raise NotImplementedError()

    def decrypt(self, encrypted_data: Any):
        raise NotImplementedError()


class KeyIsNotDefinedError(RuntimeError):
    pass
