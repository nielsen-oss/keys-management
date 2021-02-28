from typing import Dict

from . import KeyState, UndefinedOperationError
from .. import Key, KeysStore
from ..consts import STATE

class UnknownState(KeyState):
    def to_dict(self) -> Dict:
        return {
            STATE: 'unknown'
        }

    def set_key(self, key):
        raise UndefinedOperationError('set_key', 'in UnknownState')

    def __init__(self):
        super().__init__(None)

    def enter(self) -> None:
        raise UndefinedOperationError('enter', 'in UnknownState')

    def exit(self) -> None:
        raise UndefinedOperationError('exit', 'in UnknownState')

    def is_use_for_encrypt(self) -> bool:
        raise UndefinedOperationError('is_use_for_encrypt', 'in UnknownState')

    def get_key(self) -> Key:
        raise UndefinedOperationError('get_key', 'in UnknownState')

    def set_keys_store(self, key_store: KeysStore) -> None:
        raise UndefinedOperationError('set_keys_store', 'in UnknownState')

    def get_name(self) -> str:
        return 'UnknownState'
