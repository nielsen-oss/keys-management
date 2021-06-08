from __future__ import annotations
import logging
from typing import TYPE_CHECKING, Callable, Dict, Optional, Union, cast
from .consts import KEY, STATE, TRACE_LEVEL, TRACE_LEVEL_NAME
from .dependecies import CryptoTool, StateRepoInterface
from .errors import (FetchAndSetStateFromRepoError, GetKeyError, InvalidKeyStateError,
    KeyChangedError, KeyIsNotDefinedError, OnKeyChangedCallbackErrorStrategy,)
from .key_changed_utils import KeyChangedContext
from .log_messages_consts import (CLEAN_KEYS_LOG_FORMAT, CLEAN_PREV_KEYS_LOG_FORMAT,
    DEFINE_KEY_LOG_FORMAT, GET_KEY_DEBUG_FORMAT, GET_KEY_INFO_FORMAT,
    KEY_CHANGED_DEBUG_FORMAT, KEY_CHANGED_INFO_FORMAT, ON_HALT_LOG_FORMAT,
    ON_SKIP_LOG_FORMAT, REGISTER_ON_CHANGE_LOG_FORMAT, RV_KEY_LOG_FORMAT,
    SUCCESS_DEFINE_KEY_LOG_FORMAT,)
from .secret_key import (InvalidUseCaseNameError, SecretKeyValue, SecretKeyDefinition,
                         SecretKeyPair, SecretKeyUseCase, )

if TYPE_CHECKING:
    from .key_changed_utils import KeyChangedCallback
    from .secret_key import KeysStore, StrOrBytesPair, StrOrBytes

logging.addLevelName(TRACE_LEVEL, TRACE_LEVEL_NAME)
logger = logging.getLogger(__name__)

PURPOSE_IS_NOT_USECASE_TYPE_MSG = 'purpose argument is not type of "SecretKeyUseCase"'
PURPOSE_IS_NOT_AUTHENTICATION_MSG = "purpose is not SecretKeyUseCase.AUTHENTICATION"
DEFAULT_CALLBACK_NAME_FORMAT = "{}_callback_{}"


class KeysManagement(object):
    """
    This is the main interface class who exposes the library functionalities API.
    """

    def define_key(
        self,
        name: str,
        keys_store: KeysStore,
        use_case: SecretKeyUseCase,
        stateless: bool,
        target_data_accessible: bool,
        keep_in_cache: bool,
        on_key_changed_callback_error_strategy: OnKeyChangedCallbackErrorStrategy = None,
    ) -> KeysManagement:
        raise NotImplementedError()

    def get_key(
        self, key_name: str, purpose: SecretKeyUseCase = None
    ) -> StrOrBytes:
        raise NotImplementedError()

    def get_encrypt_key(self, key_name: str) -> StrOrBytes:
        return self.get_key(key_name, SecretKeyUseCase.ENCRYPTION)

    def get_decrypt_key(self, key_name: str) -> StrOrBytes:
        return self.get_key(key_name, SecretKeyUseCase.DECRYPTION)

    def key_changed(
        self,
        key_name: str,
        old_keys: StrOrBytesPair,
        new_keys: StrOrBytesPair,
    ) -> None:
        raise NotImplementedError()

    def register_on_change(
        self,
        key_name: str,
        on_change_func: KeyChangedCallback,
        callback_id: str = None,
    ) -> None:
        raise NotImplementedError()

    def save_states(self) -> None:
        raise NotImplementedError()

    def save_state(self, key_name: str) -> None:
        raise NotImplementedError


class KeysManagementImpl(KeysManagement):
    _state_repo: StateRepoInterface
    _crypto_tool: CryptoTool
    _keys_definitions: Dict[str, SecretKeyDefinition]
    _callbacks_executions_error_handling: Dict[
        OnKeyChangedCallbackErrorStrategy, Callable
    ]

    def __init__(self, state_repo: StateRepoInterface, crypto_tool: CryptoTool):
        self._state_repo = state_repo
        self._crypto_tool = crypto_tool
        self._keys_definitions = {}
        self._callbacks_executions_error_handling = {
            OnKeyChangedCallbackErrorStrategy.HALT: KeysManagementImpl._on_halt_strategy,
            OnKeyChangedCallbackErrorStrategy.SKIP: KeysManagementImpl._on_skip_strategy,
            OnKeyChangedCallbackErrorStrategy.SKIP_AND_RAISE: KeysManagementImpl._on_skip_and_raise_strategy,
            OnKeyChangedCallbackErrorStrategy.RAISE_IMMEDIATELY: KeysManagementImpl._on_raise_strategy,
        }

    def define_key(
        self,
        name: str,
        keys_store: KeysStore,
        use_case: SecretKeyUseCase,
        stateless: bool = None,
        target_data_accessible: bool = None,
        keep_in_cache: bool = None,
        on_key_changed_callback_error_strategy: OnKeyChangedCallbackErrorStrategy = None,
    ) -> KeysManagement:
        on_key_changed_callback_error_strategy = (
            on_key_changed_callback_error_strategy
            if on_key_changed_callback_error_strategy is not None
            else OnKeyChangedCallbackErrorStrategy.HALT
        )
        logger.info(DEFINE_KEY_LOG_FORMAT % name)
        key_definition = SecretKeyDefinition(
            name,
            keys_store,
            use_case=use_case,
            stateless=stateless,
            target_data_accessible=target_data_accessible,
            keep_in_cache=keep_in_cache,
            on_key_changed_callback_error_strategy=on_key_changed_callback_error_strategy,
        )
        logger.debug(SUCCESS_DEFINE_KEY_LOG_FORMAT % str(key_definition))
        self._keys_definitions[name] = key_definition
        return self

    def get_key(
        self, key_name: str, purpose: SecretKeyUseCase = None
    ) -> StrOrBytes:
        try:
            if not logger.isEnabledFor(logging.DEBUG):
                logger.info(GET_KEY_INFO_FORMAT.format(key_name))
            self._validate_key_name(key_name)
            key_definition = self._keys_definitions[key_name]
            purpose = (
                self._determine_get_key_purpose(key_definition)
                if purpose is None
                else purpose
            )
            logger.debug(GET_KEY_DEBUG_FORMAT.format(key_name, purpose.name))
            rv_key = self._get_key_by_use_case(key_definition, purpose)
            logger.debug(RV_KEY_LOG_FORMAT, str(rv_key))
            self._update_key_definition_state(key_definition, purpose)
            return rv_key.get_value()
        except GetKeyError as e:
            raise e
        except Exception as e:
            raise GetKeyError(key_name) from e

    def _get_key_by_use_case(
        self,
        key_definition: SecretKeyDefinition,
        purpose: SecretKeyUseCase,
    ) -> SecretKeyValue:
        if key_definition.use_case == SecretKeyUseCase.ENCRYPTION_DECRYPTION:
            return self._get_key_encryption_decryption_case(key_definition, purpose)
        else:
            return self._get_key_authentication_case(key_definition, purpose)

    def _update_key_definition_state(
        self, key_definition: SecretKeyDefinition, purpose: SecretKeyUseCase
    ) -> None:
        # todo test it
        logger.log(TRACE_LEVEL, CLEAN_KEYS_LOG_FORMAT % key_definition.name)
        key_definition.clean_keys()
        key_definition.set_last_use_case(purpose)
        if self._is_clean_previous_keys(key_definition, purpose):
            logger.log(TRACE_LEVEL, CLEAN_PREV_KEYS_LOG_FORMAT % key_definition.name,
            )
            key_definition.clean_previous_keys()


    @staticmethod
    def _is_clean_previous_keys(
        key_definition: SecretKeyDefinition,
        current_purpose: SecretKeyUseCase,
    ) -> bool:
        return current_purpose == SecretKeyUseCase.AUTHENTICATION or (
            current_purpose == SecretKeyUseCase.DECRYPTION
            and not key_definition.is_keep_in_cache()
        )

    def _get_key_authentication_case(
        self,
        key_definition: SecretKeyDefinition,
        purpose: SecretKeyUseCase,
    ) -> SecretKeyValue:
        if purpose != SecretKeyUseCase.AUTHENTICATION:
            GetKeyError(
                key_name=key_definition.name,
                reason=PURPOSE_IS_NOT_AUTHENTICATION_MSG,
            )
        return SecretKeyValue(cast(Union[str, bytes], key_definition.keys_store()))

    def _get_key_encryption_decryption_case(
        self,
        key_definition: SecretKeyDefinition,
        purpose: SecretKeyUseCase,
    ) -> SecretKeyValue:
        if purpose == SecretKeyUseCase.ENCRYPTION:
            return self._get_key_for_encryption(key_definition)
        else:  # purpose == SecretKeyUseCase.DECRYPTION:
            return self._get_key_for_decryption(key_definition)

    def _get_key_for_decryption(self, key_definition: SecretKeyDefinition) -> SecretKeyValue:
        if not key_definition.has_keys():
            if (
                key_definition.get_last_use_case() is None
                and key_definition.is_stated()
            ):
                self._fetch_and_set_state_from_repo(key_definition)
                if not key_definition.has_keys():
                    key_definition.set_keys_from_store()
            else:
                key_definition.set_keys_from_store()
        return key_definition.get_previous_or_current_keys().decrypt_key  # type: ignore[union-attr]

    def _get_key_for_encryption(self, key_definition: SecretKeyDefinition) -> SecretKeyValue:
        key_definition.set_keys_from_store()
        return key_definition.keys.encrypt_key  # type: ignore[union-attr]

    def _determine_get_key_purpose(
        self, key_definition: SecretKeyDefinition
    ) -> SecretKeyUseCase:
        if key_definition.use_case not in {
            SecretKeyUseCase.ENCRYPTION_DECRYPTION,
            None,
        }:
            return key_definition.use_case
        else:
            return self.__determine_get_key_purpose_by_previous_use(key_definition)

    def __determine_get_key_purpose_by_previous_use(
        self, key_definition: SecretKeyDefinition
    ) -> SecretKeyUseCase:
        prev_use = self.__get_previous_use(key_definition)
        if prev_use == SecretKeyUseCase.ENCRYPTION:
            return SecretKeyUseCase.DECRYPTION
        else:
            return SecretKeyUseCase.ENCRYPTION

    def __get_previous_use(
        self, key_definition: SecretKeyDefinition
    ) -> Optional[SecretKeyUseCase]:
        prev_use = key_definition.get_last_use_case()
        if prev_use is None and key_definition.is_stated():
            self._fetch_and_set_state_from_repo(key_definition)
            prev_use = key_definition.get_last_use_case()
        return prev_use

    def _fetch_and_set_state_from_repo(
        self, key_definition: SecretKeyDefinition
    ) -> None:
        try:
            raw_state = self._crypto_tool.decrypt(
                self._state_repo.read_state(key_definition.name)
            )
            key_definition.set_last_use_case(SecretKeyUseCase.get(raw_state[STATE]))
            if KEY in raw_state:
                key_definition.set_previous_keys(raw_state[KEY])
        except InvalidUseCaseNameError as e:
            raise InvalidKeyStateError(key_definition.name) from e
        except Exception as e:
            raise FetchAndSetStateFromRepoError(key_definition.name) from e

    def key_changed(
        self,
        key_name: str,
        old_keys: StrOrBytesPair,
        new_keys: StrOrBytesPair,
    ) -> None:
        try:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    KEY_CHANGED_DEBUG_FORMAT.format(
                        key_name,
                        str(SecretKeyPair(old_keys)),
                        str(SecretKeyPair(new_keys)),
                    )
                )
            else:
                logger.info(KEY_CHANGED_INFO_FORMAT.format(key_name))
            self._validate_key_name(key_name)
            key_changed_context: KeyChangedContext = self._create_context(
                self._keys_definitions[key_name], old_keys, new_keys
            )
            key_changed_context.run_callbacks()
        except KeyIsNotDefinedError as e:
            raise KeyChangedError(key_name) from e
        except DoNothing:
            pass

    @staticmethod
    def _on_halt_strategy(
        key_name: str,
        callback_name: str,
        key_changed_context: KeyChangedContext,
    ) -> None:
        logger.error(
            ON_HALT_LOG_FORMAT.format(
                key_name=key_name,
                callback_name=callback_name,
                error=key_changed_context[callback_name]["error"],
            )
        )
        raise DoNothing()

    @staticmethod
    def _on_skip_strategy(
        key_name: str,
        callback_name: str,
        key_changed_context: KeyChangedContext,
    ) -> None:
        logger.error(
            ON_SKIP_LOG_FORMAT.format(
                key_name=key_name,
                callback_name=callback_name,
                error=key_changed_context[callback_name]["error"],
            )
        )

    @staticmethod
    def _on_skip_and_raise_strategy(
        key_name: str,
        callback_name: str,
        key_changed_context: KeyChangedContext,
    ) -> None:
        pass

    @staticmethod
    def _on_raise_strategy(
        key_name: str,
        callback_name: str,
        key_changed_context: KeyChangedContext,
    ) -> None:
        raise KeyChangedError(key_name, key_changed_context)

    def _create_context(
        self,
        key_definition: SecretKeyDefinition,
        old_keys: StrOrBytesPair,
        new_keys: StrOrBytesPair,
    ) -> KeyChangedContext:
        return KeyChangedContext(
            key_definition,
            self._callbacks_executions_error_handling[
                key_definition.on_key_changed_callback_error_strategy
            ],
            old_keys,
            new_keys,
        )

    def register_on_change(
        self,
        key_name: str,
        on_change_func: KeyChangedCallback,
        callback_name: str = None,
    ) -> None:
        self._validate_key_name(key_name)
        callbacks = self._keys_definitions[key_name].on_change_callbacks
        callback_name = (
            callback_name
            if callback_name is not None
            else DEFAULT_CALLBACK_NAME_FORMAT.format(key_name, str(len(callbacks) + 1))
        )
        callbacks[callback_name] = on_change_func

    def _validate_key_name(self, key_name: str) -> None:
        logger.info(REGISTER_ON_CHANGE_LOG_FORMAT % key_name)
        if key_name not in self._keys_definitions:
            raise KeyIsNotDefinedError(key_name)

    def save_state(self, key_name: str) -> None:
        self._validate_key_name(key_name)
        last_use_case = self._keys_definitions[key_name].get_last_use_case()
        raw_state = {STATE: last_use_case}
        if last_use_case == SecretKeyUseCase.ENCRYPTION:
            key = self.get_decrypt_key(key_name)
            if key is not None:
                raw_state[KEY] = key  # type: ignore[assignment]
        self._write_state(key_name, raw_state)

    def _write_state(self, key_name: str, state: Dict) -> None:
        self._state_repo.write_state(key_name, self._crypto_tool.encrypt(state))

    def save_states(self) -> None:
        for key_name, key_definition in self._keys_definitions.items():
            if key_definition.is_stated():
                self.save_state(key_name)


class DoNothing(Exception):
    pass
