from __future__ import annotations
from typing import Callable, Optional, Dict

Key = str
KeysStore = Callable
OnChange = Callable
KeysPair = Dict[str, Key]


class KeysManagementInterface(object):
    def define_key(self, key_name: str, keys_store: KeysStore, keep_state: bool = False) -> KeysManagementInterface:
        raise NotImplementedError()

    def get_key(self, key_name: str, is_for_encrypt: bool = None) -> Key:
        raise NotImplementedError()

    def key_changed(self, key_name: str, old_key: Key, new_key: Key, new_key_store: Optional[KeysStore] = None):
        raise NotImplementedError()

    def on_change(self, key_name: str, on_change_func: OnChange):
        raise NotImplementedError()


class StateRepoInterface(object):
    def write_state(self, key, key_state) -> None:
        raise NotImplementedError()

    def read_state(self, key) -> Dict:
        raise NotImplementedError()


class CryptoTool(object):
    def encrypt(self, data):
        raise NotImplementedError()

    def decrypt(self, encrypted_data):
        raise NotImplementedError()


class KeyIsNotDefinedError(RuntimeError):
    pass
