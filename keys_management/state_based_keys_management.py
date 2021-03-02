from typing import Optional, Dict, List
import logging
from . import KeysManagement, StateRepoInterface, CryptoTool, KeysStore, KeyIsNotDefinedError, OnChange
from .consts import STATE, DECRYPTED_STATE, KEY
from .key_state import KeyState
from .key_state.state_factory import StateFactory
from .key_state.unknown_state import UnknownState
from .secret_key import SecretKeyPairValues, SecretKeyValue


logger = logging.getLogger(__name__)


class SecretKeyDefinition:
    _name: str
    _keys_store: KeysStore
    _is_stateless: bool
    _current_state: KeyState
    _on_change_callbacks: List[OnChange]

    def __init__(self, name: str, keys_store: KeysStore, is_stateless: bool):
        self._name = name
        self._keys_store = keys_store
        self._is_stateless = is_stateless
        self._current_state = UnknownState()
        self._on_change_callbacks = []

    @property
    def name(self) -> str:
        return self._name

    def is_stateless(self) -> bool:
        return self._is_stateless

    def is_stated(self) -> bool:
        return not self._is_stateless

    @property
    def state(self) -> KeyState:
        return self._current_state

    @property
    def on_change_callbacks(self) -> List[OnChange]:
        return self._on_change_callbacks

    @property
    def keys_store(self) -> KeysStore:
        return self._keys_store

    def change_state(self, new_state: KeyState):
        self._current_state = new_state


KeyDefinitions = Dict[str, SecretKeyDefinition]


class KeysManagementStateBased(KeysManagement):
    state_repo: StateRepoInterface
    crypto_tool: CryptoTool
    key_definitions: KeyDefinitions

    def __init__(self, state_repo: StateRepoInterface, crypto_tool: CryptoTool):
        self.state_repo = state_repo
        self.crypto_tool = crypto_tool
        self.key_definitions = {}

    def define_key(self, key_name: str, initial_keys_store: KeysStore, is_stateless: bool = True) -> KeysManagement:
        logger.info('Defining the key "%s"' % key_name)
        self.key_definitions[key_name] = SecretKeyDefinition(key_name, initial_keys_store, is_stateless)
        return self

    def get_key(self, key_name: str, is_for_encrypt: bool = None) -> SecretKeyValue:
        logger.info('requested to get key for "%s"' % key_name)
        self._validate_key_name(key_name)
        current_state: KeyState = self._get_state(key_name)
        logger.debug('current state for "{}" is "{}"'.format(key_name, current_state.get_name()))
        rv_key: SecretKeyValue = current_state.get_key().get_value()
        if self._should_change_state(current_state, is_for_encrypt):
            self._change_state(key_name, current_state)
        return rv_key

    def _validate_key_name(self, key_name: str) -> None:
        if key_name not in self.key_definitions:
            raise KeyIsNotDefinedError(key_name)

    def _get_state(self, key_name: str) -> KeyState:
        key_definition: SecretKeyDefinition = self.key_definitions[key_name]
        current_state: KeyState = key_definition.state
        if current_state.get_name() == 'UnknownState':
            self._set_known_state(key_definition)
            return key_definition.state
        else:
            return current_state

    def _set_known_state(self, key_definition: SecretKeyDefinition) -> None:
        if key_definition.is_stated():
            known_state = self._fetch_state(key_definition)
        else:
            known_state = StateFactory.create_state(DECRYPTED_STATE, key_definition.keys_store)
        key_definition.change_state(known_state)
        known_state.enter()

    def _fetch_state(self, key_definition: SecretKeyDefinition) -> KeyState:
        raw_state = self.crypto_tool.decrypt(self.state_repo.read_state(key_definition.name))
        return StateFactory.create_state(raw_state[STATE], key_definition.keys_store, raw_state.get(KEY, None))

    @staticmethod
    def _should_change_state(current_state: KeyState, is_for_encrypt: bool = None) -> bool:
        return not isinstance(is_for_encrypt, bool) or current_state.is_use_for_encrypt() == is_for_encrypt

    def _write_state(self, key_name: str, state: Dict) -> None:
        self.state_repo.write_state(key_name, self.crypto_tool.encrypt(state))

    def _change_state(self, key_name: str, current_state: KeyState) -> KeysManagement:
        opposite_state: KeyState = current_state.get_opposite_state()
        logger.debug('going to change the key state for "{}" from "{}" to "{}"'.format(key_name, current_state.get_name(), opposite_state.get_name()))
        current_state.exit()
        opposite_state.enter()
        self.key_definitions[key_name].change_state(opposite_state)
        return self

    def key_changed(self, key_name: str, old_keys: SecretKeyPairValues, new_keys: SecretKeyPairValues, new_key_store: Optional[KeysStore] = None) -> None:
        if logger.isEnabledFor(logging.DEBUG):
            pass
        logger.info('the key "{}" is changed, registered callbacks will be executed'.format(key_name))
        for callback in self.key_definitions[key_name].on_change_callbacks:
            callback(old_keys, new_keys)

    def register_on_change(self, key_name: str, on_change_func: OnChange) -> None:
        logger.info('registering new OnChange callback for "%s"' % key_name)
        self._validate_key_name(key_name)
        self.key_definitions[key_name].on_change_callbacks.append(on_change_func)

    def save_state(self, key_name: str):
        self._validate_key_name(key_name)
        raw_state = self.key_definitions[key_name].state.to_dict()
        self._write_state(key_name, raw_state)

    def save_states(self):
        for key_name, key_definition in self.key_definitions.items():
            if key_definition.is_stated():
                self.save_state(key_name)
