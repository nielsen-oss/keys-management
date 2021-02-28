from __future__ import annotations
from typing import Callable, Optional, Dict, Union, Tuple, Any

Key = str
KeysStore = Callable[[], Union[str, Tuple[str, str], Dict[str, str]]]
OnChange = Callable[[str, str], None]
KeysPair = Dict[str, Key]


class KeysManagement(object):
    def define_key(self, key_name: str, keys_store: KeysStore, keep_state: bool = False) -> KeysManagement:
        raise NotImplementedError()

    def get_key(self, key_name: str, is_for_encrypt: bool = None) -> Key:
        raise NotImplementedError()

    def key_changed(self, key_name: str, old_key: Key, new_key: Key, new_key_store: Optional[KeysStore] = None) -> None:
        raise NotImplementedError()

    def on_change(self, key_name: str, on_change_func: OnChange) -> None:
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
