from __future__ import annotations
from typing import Optional, Dict, TYPE_CHECKING
import logging
from .key_definition import SecretKeyDefinition
from .consts import DECRYPTED_STATE, AUTHENTICATION_STATE, TEMP_STATE_NAME
from .. import KeysManagement, StateRepoInterface, CryptoTool, KeyIsNotDefinedError
from ..consts import STATE, KEY, DEFINE_KEY_LOG_MESSAGE, GET_KEY_INFO_MESSAGE, LOG_GEY_DEBUG_MESSAGE, KEY_CHANGED_DEBUG_MESSAGE, KEY_CHANGED_INFO_MESSAGE, REGISTER_ON_CHANGE_LOG_MESSAGE
from ..state_based.key_state import KeyState
from ..state_based.key_state.state_factory import StateFactory
from ..state_based.key_state.unknown_state import UnknownState
from ..secret_key import SecretKeyPair, SecretKey, SecretKeyUseCase
if TYPE_CHECKING:
    from ..secret_key import SecretKeyPairValues, SecretKeyValue
    from .. import KeysStore, KeyChangedCallback
logger = logging.getLogger(__name__)

KeyDefinitions = Dict[str, SecretKeyDefinition]


class KeysManagementStateBased(KeysManagement):
    state_repo: StateRepoInterface
    crypto_tool: CryptoTool
    key_definitions: KeyDefinitions

    def __init__(self, state_repo: StateRepoInterface, crypto_tool: CryptoTool):
        self.state_repo = state_repo
        self.crypto_tool = crypto_tool
        self.key_definitions = {}

    def define_key(self, name: str, keys_store: KeysStore, is_stateless: bool, use_case: SecretKeyUseCase, is_target_data_accessible: bool) -> KeysManagement:
        logger.info(DEFINE_KEY_LOG_MESSAGE % name)
        self.key_definitions[name] = SecretKeyDefinition(name, keys_store, is_stateless, use_case, is_target_data_accessible)
        return self

    def get_key(self, key_name: str, purpose: SecretKeyUseCase) -> SecretKeyValue:
        logger.info(GET_KEY_INFO_MESSAGE.format(key_name))
        self._validate_key_name(key_name)
        current_state: KeyState = self._get_state(key_name)
        logger.debug('current state for "{}" is "{}"'.format(key_name, current_state.get_name()))
        rv_key: SecretKey = current_state.get_key()
        logger.debug(LOG_GEY_DEBUG_MESSAGE, str(rv_key))
        if self._should_change_state(current_state, purpose):
            self._change_state(key_name, current_state)
        return rv_key.get_value()

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
        if key_definition.use_case == SecretKeyUseCase.AUTHENTICATION:
            known_state = StateFactory.create_state(AUTHENTICATION_STATE, key_definition.keys_store)
        elif key_definition.is_stated():
            known_state = self._fetch_state(key_definition)
        else:
            known_state = StateFactory.create_state(DECRYPTED_STATE, key_definition.keys_store)
        key_definition.change_state(known_state)
        known_state.enter()

    def _fetch_state(self, key_definition: SecretKeyDefinition) -> KeyState:
        raw_state = self.crypto_tool.decrypt(self.state_repo.read_state(key_definition.name))
        require_state_name = TEMP_STATE_NAME if key_definition.is_target_data_accessible else raw_state[STATE]
        return StateFactory.create_state(require_state_name, key_definition.keys_store, raw_state.get(KEY, None))

    @staticmethod
    def _should_change_state(current_state: KeyState, purpose: SecretKeyUseCase) -> bool:
        return not isinstance(purpose, SecretKeyUseCase) or current_state.get_use_case() == purpose

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
            logger.debug(KEY_CHANGED_DEBUG_MESSAGE.format(key_name, str(SecretKeyPair(old_keys)), str(SecretKeyPair(new_keys))))
        else:
            logger.info(KEY_CHANGED_INFO_MESSAGE.format(key_name))
        for callback in self.key_definitions[key_name].on_change_callbacks:
            callback(old_keys, new_keys)

    def register_on_change(self, key_name: str, on_change_func: KeyChangedCallback) -> None:
        logger.info(REGISTER_ON_CHANGE_LOG_MESSAGE % key_name)
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
