from __future__ import annotations
from typing import Dict, Optional, Union, TYPE_CHECKING
import logging
from .secret_key import SecretKeyUseCase, SecretKeyDefinition, SecretKey, InvalidUseCaseNameError, SecretKeyPair
from .on_change_key_definition import OnChangeKeyDefinition, OnChangeKeyDefinitionInitError
from .dependecies import StateRepoInterface, CryptoTool
from .consts import DEFINE_KEY_LOG_MESSAGE, DEFINE_KEY_DEBUG_MESSAGE, GET_KEY_INFO_MESSAGE, GET_KEY_DEBUG_MESSAGE,\
    LOG_GEY_DEBUG_MESSAGE, TRACE_LEVEL, TRACE_LEVEL_NAME, STATE, KEY, KEY_CHANGED_INFO_MESSAGE, KEY_CHANGED_DEBUG_MESSAGE,\
    REGISTER_ON_CHANGE_LOG_MESSAGE
from .errors import KeysManagementError, OnKeyChangedCallbackErrorStrategy

if TYPE_CHECKING:
    from .secret_key import KeysStore, SecretKeyValue, SecretKeyPairValues
    from .key_changed_callback import KeyChangedCallback


logging.addLevelName(TRACE_LEVEL, TRACE_LEVEL_NAME)
logger = logging.getLogger(__name__)


class KeysManagement(object):
    def define_key(self, name: str, keys_store: KeysStore, is_stateless: bool, use_case: SecretKeyUseCase, target_data_accessible: bool, keep_in_cache: bool) -> KeysManagement:
        raise NotImplementedError()

    def get_key(self, key_name: str, purpose: SecretKeyUseCase = None) -> SecretKeyValue:
        raise NotImplementedError()

    def get_encrypt_key(self, key_name: str) -> SecretKeyValue:
        return self.get_key(key_name, SecretKeyUseCase.ENCRYPTION)

    def get_decrypt_key(self, key_name: str) -> SecretKeyValue:
        return self.get_key(key_name, SecretKeyUseCase.DECRYPTION)

    def key_changed(self, key_name: str, old_keys: SecretKeyPairValues, new_keys: SecretKeyPairValues) -> None:
        raise NotImplementedError()

    def register_on_change(self, key_name: str, on_change_func: KeyChangedCallback, callback_id: str = None) -> None:
        raise NotImplementedError()

    def save_states(self) -> None:
        raise NotImplementedError()

    def save_state(self, key_name: str) -> None:
        raise NotImplementedError


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
        logger.info(DEFINE_KEY_LOG_MESSAGE % name)
        key_definition = SecretKeyDefinition(name,
                                             keys_store,
                                             use_case=use_case,
                                             stateless=stateless,
                                             target_data_accessible=target_data_accessible,
                                             keep_in_cache=keep_in_cache)
        logger.debug(DEFINE_KEY_DEBUG_MESSAGE % str(key_definition))
        self._keys_definitions[name] = key_definition
        return self

    def get_key(self, key_name: str, purpose: SecretKeyUseCase = None) -> SecretKeyValue:
        try:
            if not logger.isEnabledFor(logging.DEBUG):
                logger.info(GET_KEY_INFO_MESSAGE.format(key_name))
            self._validate_key_name(key_name)
            key_definition: SecretKeyDefinition = self._keys_definitions[key_name]
            purpose = self._determine_get_key_purpose(purpose, key_definition) if purpose is None else purpose
            logger.debug(GET_KEY_DEBUG_MESSAGE.format(key_name, purpose.name))
            rv_key = self._get_key_by_use_case(key_definition, purpose)
            logger.debug(LOG_GEY_DEBUG_MESSAGE, str(rv_key))
            self._update_key_definition_state(key_definition, purpose)
            return rv_key.get_value()
        except GetKeyError as e:
            raise e
        except Exception as e:
            raise GetKeyError("failed to get key for %s" % key_name) from e

    def _get_key_by_use_case(self, key_definition: SecretKeyDefinition, purpose: SecretKeyUseCase):
        if key_definition.use_case == SecretKeyUseCase.ENCRYPTION_DECRYPTION:
            return self._get_key_encryption_decryption_case(key_definition, purpose)
        else:
            return self._get_key_authentication_case(key_definition, purpose)

    def _update_key_definition_state(self, key_definition, purpose):
        logger.log(TRACE_LEVEL, "clean '%s' keys from cache" % key_definition.name)
        key_definition.clean_keys()
        key_definition.set_last_use_case(purpose)
        if self._is_clean_previous_keys(key_definition, purpose):
            logger.log(TRACE_LEVEL, "clean previous '%s' keys from cache" % key_definition.name)
            key_definition.clean_previous_keys()

    @staticmethod
    def _is_clean_previous_keys(key_definition: SecretKeyDefinition, current_purpose: SecretKeyUseCase):
        return current_purpose == SecretKeyUseCase.AUTHENTICATION or (
                current_purpose == SecretKeyUseCase.DECRYPTION and not key_definition.is_keep_in_cache())

    def _get_key_authentication_case(self, key_definition: SecretKeyDefinition,
                                     purpose: SecretKeyUseCase) -> SecretKey:
        if purpose != SecretKeyUseCase.AUTHENTICATION:
            GetKeyError(key_name=key_definition.name, reason="purpose is not SecretKeyUseCase.AUTHENTICATION")
        return SecretKey(key_definition.keys_store())

    def _get_key_encryption_decryption_case(self, key_definition: SecretKeyDefinition,
                                            purpose: SecretKeyUseCase) -> SecretKey:
        if purpose == SecretKeyUseCase.ENCRYPTION:
            return self._get_key_for_encryption(key_definition)
        elif purpose == SecretKeyUseCase.DECRYPTION:
            return self._get_key_for_decryption(key_definition)

    def _get_key_for_decryption(self, key_definition: SecretKeyDefinition) -> SecretKey:
        if not key_definition.has_keys():
            if key_definition.get_last_use_case() is None and key_definition.is_stated():
                self._fetch_and_set_state_from_repo(key_definition)
                if not key_definition.has_keys():
                    key_definition.set_keys_from_store()
            else:
                key_definition.set_keys_from_store()
        return key_definition.get_previous_or_current_keys().decrypt_key

    def _get_key_for_encryption(self, key_definition: SecretKeyDefinition) -> SecretKey:
        key_definition.set_keys_from_store()
        return key_definition.keys.encrypt_key

    def _determine_get_key_purpose(self, purpose: Optional[SecretKeyUseCase],
                                   key_definition: SecretKeyDefinition) -> SecretKeyUseCase:
        if purpose is not None and not isinstance(purpose, SecretKeyUseCase):
            raise KeysManagementError('purpose argument is not type of "SecretKeyUseCase"')
        if key_definition.use_case not in {SecretKeyUseCase.ENCRYPTION_DECRYPTION, None}:
            return key_definition.use_case
        prev_use = key_definition.get_last_use_case()
        if prev_use is None and key_definition.is_stated():
            self._fetch_and_set_state_from_repo(key_definition)
            prev_use = key_definition.get_last_use_case()
        if prev_use == SecretKeyUseCase.DECRYPTION:
            return SecretKeyUseCase.ENCRYPTION
        elif prev_use == SecretKeyUseCase.ENCRYPTION:
            return SecretKeyUseCase.DECRYPTION
        else:
            return SecretKeyUseCase.ENCRYPTION

    def _fetch_and_set_state_from_repo(self, key_definition: SecretKeyDefinition) -> None:
        try:
            raw_state = self._crypto_tool.decrypt(self._state_repo.read_state(key_definition.name))
            key_definition.set_last_use_case(SecretKeyUseCase.get(raw_state[STATE]))
            if KEY in raw_state:
                key_definition.set_previous_keys(raw_state[KEY])
        except InvalidUseCaseNameError as e:
            raise InvalidKeyStateError(key_definition.name) from e
        except Exception as e:
            raise FetchAndSetStateFromRepoError(key_definition.name) from e

    def key_changed(self, key_name: str, old_keys: SecretKeyPairValues, new_keys: SecretKeyPairValues) -> None:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                KEY_CHANGED_DEBUG_MESSAGE.format(key_name, str(SecretKeyPair(old_keys)), str(SecretKeyPair(new_keys))))
        else:
            logger.info(KEY_CHANGED_INFO_MESSAGE.format(key_name))
        self._validate_key_name(key_name)
        key_definition = self._keys_definitions[key_name]
        # what_to_do_on_error = key_definition.
        on_change_key_definition = OnChangeKeyDefinition(key_definition)
        for callback_name, callback in self._keys_definitions[key_name].on_change_callbacks.items():
            try:
                callback(old_keys, new_keys, on_change_key_definition)
            except Exception as e:
                if key_definition.on_key_changed_error == OnKeyChangedCallbackErrorStrategy.HALT:
                    logger.error('Halt onChange callbackes execution of "{}": Failed to execute {}'.format(key_name,
                                                                                                           callback_name))
                    break
                elif key_definition.on_key_changed_error == OnKeyChangedCallbackErrorStrategy.SKIP:
                    pass

    def register_on_change(self, key_name: str, on_change_func: KeyChangedCallback, callback_name: str = None) -> None:
        self._validate_key_name(key_name)
        callbacks = self._keys_definitions[key_name].on_change_callbacks
        callback_name = callback_name if callback_name is not None else "{}_callback_{}".format(key_name,
                                                                                                str(len(callbacks) + 1))
        callbacks[callback_name] = on_change_func

    def _validate_key_name(self, key_name: str) -> None:
        logger.info(REGISTER_ON_CHANGE_LOG_MESSAGE % key_name)
        if key_name not in self._keys_definitions:
            raise KeyIsNotDefinedError(key_name)

    def save_state(self, key_name: str) -> None:
        self._validate_key_name(key_name)
        last_use_case = self._keys_definitions[key_name].get_last_use_case()
        raw_state = {STATE: last_use_case}
        if last_use_case == SecretKeyUseCase.ENCRYPTION:
            key = self.get_decrypt_key(key_name)
            if key is not None:
                raw_state[KEY] = key
        self._write_state(key_name, raw_state)

    def save_states(self) -> None:
        for key_name, key_definition in self._keys_definitions.items():
            if key_definition.is_stated():
                self.save_state(key_name)


class GetKeyError(KeysManagementError):
    def __init__(self, key_name: str, reason: str = None) -> None:
        super().__init__("failed to get key for {key_name}: {reason}".format(key_name=key_name, reason=reason if reason else ''))


class KeyIsNotDefinedError(KeysManagementError):

    def __init__(self, key_name) -> None:
        super().__init__(key_name)

    def __str__(self):
        return "KeyIsNotDefinedError: key_name is '%s'" % self.args[0]


class FetchAndSetStateFromRepoError(KeysManagementError):
    def __init__(self, key_name: str, why: str = None) -> None:
        super().__init__('Failed to fetch and set key state for {key_name} from_repo: {why}'.format(key_name=key_name, why=why if why else ""))


class InvalidKeyStateError(FetchAndSetStateFromRepoError):

    def __init__(self, key_name: str, why: str = None) -> None:
        super().__init__(key_name, why)

