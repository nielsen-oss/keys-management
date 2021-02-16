from . import KeyState, UndefinedOperationError
from .. import Key, KeysStore


class UnknownState(KeyState):
    def __init__(self):
        super().__init__(None)

    def on_enter(self) -> None:
        raise UndefinedOperationError('on_enter', 'in UnknownState')

    def on_exit(self) -> None:
        raise UndefinedOperationError('on_exit', 'in UnknownState')

    def is_use_for_encrypt(self) -> bool:
        raise UndefinedOperationError('is_use_for_encrypt', 'in UnknownState')

    def get_key(self) -> Key:
        raise UndefinedOperationError('get_key', 'in UnknownState')

    def set_keys_store(self, key_store: KeysStore) -> None:
        raise UndefinedOperationError('set_keys_store', 'in UnknownState')

    @property
    def name(self):
        return 'UnknownState'
