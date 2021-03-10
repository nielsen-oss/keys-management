from typing import Optional, Dict
import logging
from keys_management import KeysManagement, OnChange, KeysStore, SecretKeyUseCase, SecretKeyValue, \
    StateRepoInterface, CryptoTool, KeyIsNotDefinedError
from keys_management.secret_key import BaseSecretKeyDefinition, SecretKeyPair, SecretKeyState, SecretKeyPairValues, OnChangeKeyDefinition, InvalidUseCaseName
from keys_management.consts import STATE, KEY

logger = logging.getLogger(__name__)


class SecretKeyDefinition(BaseSecretKeyDefinition, SecretKeyState):
    _last_use: Optional[SecretKeyUseCase]
    _current_keys: Optional[SecretKeyPair]
    _previous_keys: Optional[SecretKeyPair]

    def __init__(self, name: str, keys_store: KeysStore, **kwargs):
        super(SecretKeyDefinition, self).__init__(name, keys_store, **kwargs)
        self._last_use = None
        self._current_keys = None
        self._previous_keys = None

    def set_keys_from_store(self) -> None:
        self._previous_keys = self._current_keys
        self._current_keys = SecretKeyPair(self._keys_store())

    @property
    def keys(self) -> SecretKeyPair:
        return self._current_keys

    @property
    def previous_keys(self) -> SecretKeyPair:
        return self._previous_keys

    def set_previous_keys(self, keys: SecretKeyPairValues):
        self._current_keys = SecretKeyPair(keys)

    def get_keys_or_previous(self) -> SecretKeyPair:
        if self._current_keys is not None:
            return self._current_keys
        else:
            return self._previous_keys

    def get_previous_or_current_keys(self) -> SecretKeyPair:
        if self._previous_keys is not None:
            return self._previous_keys
        return self._current_keys

    def get_last_use_case(self) -> SecretKeyUseCase:
        return self._last_use

    def set_last_use_case(self, use_case: SecretKeyUseCase) -> None:
        self._last_use = use_case

    def has_keys(self) -> bool:
        return self._current_keys is not None or self._previous_keys is not None

    def clean_keys(self) -> None:
        self._previous_keys = self.get_keys_or_previous()
        self._current_keys = None

    def clean_previous_keys(self) -> None:
        self._previous_keys = None

    def get_key_state(self) -> SecretKeyState:
        return self

    def set_key_state(self, key_state: SecretKeyState) -> None:
        self.set_last_use_case(key_state.get_last_use_case())
        previous_keys = key_state.get_previous_keys()
        if previous_keys != self._previous_keys and previous_keys is not None:
            self.set_last_use_case(previous_keys)

    def get_previous_keys(self):
        pass

    def clean_state(self):
        self.clean_keys()
        self.clean_previous_keys()


class GetKeyError(RuntimeError):
    pass


class KeysManagementImpl(KeysManagement):
    _state_repo: StateRepoInterface
    _crypto_tool: CryptoTool
    _keys_definitions: Dict[str, SecretKeyDefinition]

    def __init__(self, state_repo: StateRepoInterface, crypto_tool: CryptoTool):
        self._state_repo = state_repo
        self._crypto_tool = crypto_tool
        self._keys_definitions = {}

    def define_key(self, name: str, keys_store: KeysStore, stateless: bool, use_case: SecretKeyUseCase,
                   target_data_accessible: bool, keep_in_cache: bool) -> KeysManagement:
        logger.info('Defining the key "%s"' % name)
        self._keys_definitions[name] = SecretKeyDefinition(name,
                                                           keys_store,
                                                           use_case=use_case,
                                                           stateless=stateless,
                                                           target_data_accessible=target_data_accessible,
                                                           keep_in_cache=keep_in_cache)
        return self

    def get_key(self, key_name: str, purpose: SecretKeyUseCase) -> SecretKeyValue:
        logger.info('requested to get key for "%s"' % key_name)
        self._validate_key_name(key_name)
        key_definition: SecretKeyDefinition = self._keys_definitions[key_name]
        rv_key: SecretKeyValue
        if key_definition.use_case == SecretKeyUseCase.AUTHENTICATION:
            rv_key = self.get_key_authentication_case(key_definition, purpose)
        if key_definition.use_case == SecretKeyUseCase.ENCRYPTION_DECRYPTION:
            if purpose is None:
                purpose = self.determine_get_key_purpose(key_definition)
            rv_key = self.get_key_encryption_decryption_case(key_definition, purpose)
        key_definition.clean_keys()
        key_definition.set_last_use_case(purpose)
        if purpose == SecretKeyUseCase.AUTHENTICATION or (
                purpose == SecretKeyUseCase.DECRYPTION and not key_definition.is_keep_in_cache()):
            key_definition.clean_previous_keys()
        return rv_key

    def get_key_authentication_case(self, key_definition: SecretKeyDefinition,
                                    purpose: SecretKeyUseCase) -> SecretKeyValue:
        if purpose != SecretKeyUseCase.AUTHENTICATION:
            GetKeyError()
        return key_definition.keys_store()

    def get_key_encryption_decryption_case(self, key_definition: SecretKeyDefinition,
                                           purpose: SecretKeyUseCase) -> SecretKeyValue:
        if purpose == SecretKeyUseCase.ENCRYPTION:
            return self.get_key_for_encryption(key_definition)
        elif purpose == SecretKeyUseCase.DECRYPTION:
            return self.get_key_for_decryption(key_definition)

    def get_key_for_decryption(self, key_definition) -> SecretKeyValue:
        if not key_definition.has_keys():
            if key_definition.get_last_use_case() is None and key_definition.is_stated():
                self._set_state(key_definition)
                if not key_definition.has_keys():
                    key_definition.set_keys_from_store()
            else:
                key_definition.set_keys_from_store()
        return key_definition.get_previous_or_current_keys().decrypt_key.get_value()

    def get_key_for_encryption(self, key_definition) -> SecretKeyValue:
        key_definition.set_keys_from_store()
        return key_definition.keys.encrypt_key.get_value()

    def determine_get_key_purpose(self, key_definition) -> SecretKeyUseCase:
        prev_use = key_definition.get_last_use_case()
        if prev_use is None and key_definition.is_stated():
            self._set_state(key_definition)
            prev_use = key_definition.get_last_use_case()
        if prev_use == SecretKeyUseCase.DECRYPTION:
            return SecretKeyUseCase.ENCRYPTION
        elif prev_use == SecretKeyUseCase.ENCRYPTION:
            return SecretKeyUseCase.DECRYPTION
        else:
            return SecretKeyPairValues.ENCRYPTION

    def _set_state(self, key_definition: SecretKeyDefinition) -> None:
        try:
            raw_state = self._crypto_tool.decrypt(self._state_repo.read_state(key_definition.name))
            key_definition.set_last_use_case(SecretKeyUseCase.get(raw_state[STATE]))
            if KEY in raw_state:
                key_definition.set_previous_keys(raw_state[KEY])
        except InvalidUseCaseName as e:
            raise InvalidKeyStateError(e)

    def key_changed(self, key_name: str, old_keys: SecretKeyPairValues, new_keys: SecretKeyPairValues) -> None:
        self._validate_key_name(key_name)
        on_change_key_definition = OnChangeKeyDefinition(self._keys_definitions[key_name])
        #todo catch errors
        for callback in self._keys_definitions[key_name].on_change_callbacks:
            callback(old_keys, new_keys, on_change_key_definition)

    def register_on_change(self, key_name: str, on_change_func: OnChange) -> None:
        self._validate_key_name(key_name)
        self._keys_definitions[key_name].on_change_callbacks.append(on_change_func)

    def _validate_key_name(self, key_name: str) -> None:
        if key_name not in self._keys_definitions:
            raise KeyIsNotDefinedError(key_name)


class InvalidKeyStateError(RuntimeError):
    pass
