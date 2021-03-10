from __future__ import annotations
from typing import Callable, Any, Union, Dict
from .secret_key import SecretKeyValue, SecretKeyPairValues, KeysStore, SecretKeyUseCase, OnChangeKeyDefinition


OnChange = Callable[[Union[SecretKeyPairValues], Union[SecretKeyPairValues], OnChangeKeyDefinition], None]


class KeysManagement(object):
    def define_key(self, name: str, keys_store: KeysStore, is_stateless: bool, use_case: SecretKeyUseCase, target_data_accessible: bool, keep_in_cache: bool) -> KeysManagement:
        raise NotImplementedError()

    def get_key(self, key_name: str, purpose: SecretKeyUseCase) -> SecretKeyValue:
        raise NotImplementedError()

    def get_encrypt_key(self, key_name: str) -> SecretKeyValue:
        return self.get_key(key_name, SecretKeyUseCase.ENCRYPTION)

    def get_decrypt_key(self, key_name: str) -> SecretKeyValue:
        return self.get_key(key_name, SecretKeyUseCase.DECRYPTION)

    def key_changed(self, key_name: str, old_keys: SecretKeyPairValues, new_keys: SecretKeyPairValues) -> None:
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
