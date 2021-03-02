from typing import Dict

from . import KeyState, UndefinedOperationError
from .. import KeysStore
from ..consts import STATE
from ..secret_key import SecretKey, SecretKeyValue


class UnknownState(KeyState):
    def __init__(self):
        super().__init__(None)

    def _concrete_enter(self):
        raise UndefinedOperationError('enter', 'in UnknownState')

    def _concrete_exit(self):
        raise UndefinedOperationError('exit', 'in UnknownState')

    def to_dict(self) -> Dict:
        return {STATE: 'unknown'}

    def set_key(self, key: SecretKey):
        raise UndefinedOperationError('set_key', 'in UnknownState')

    def is_use_for_encrypt(self) -> bool:
        raise UndefinedOperationError('is_use_for_encrypt', 'in UnknownState')

    def get_key(self) -> SecretKeyValue:
        raise UndefinedOperationError('get_key', 'in UnknownState')

    def set_keys_store(self, key_store: KeysStore) -> None:
        raise UndefinedOperationError('set_keys_store', 'in UnknownState')

    def get_name(self) -> str:
        return 'UnknownState'
