from __future__ import annotations
from typing import Dict, Optional, TYPE_CHECKING, Callable
import logging
from .secret_key import (
    SecretKeyUseCase,
    SecretKeyDefinition,
    SecretKey,
    InvalidUseCaseNameError,
    SecretKeyPair,
)
from .dependecies import StateRepoInterface, CryptoTool
from .consts import TRACE_LEVEL, TRACE_LEVEL_NAME, STATE, KEY
from .log_messages_consts import (
    DEFINE_KEY_LOG_FORMAT,
    SUCCESS_DEFINE_KEY_LOG_FORMAT,
    GET_KEY_INFO_FORMAT,
    GET_KEY_DEBUG_FORMAT,
    RV_KEY_LOG_FORMAT,
    KEY_CHANGED_INFO_FORMAT,
    KEY_CHANGED_DEBUG_FORMAT,
    REGISTER_ON_CHANGE_LOG_FORMAT,
    ON_HALT_LOG_FORMAT,
    ON_SKIP_LOG_FORMAT,
    CLEAN_KEYS_LOG_FORMAT,
    CLEAN_PREV_KEYS_LOG_FORMAT,
)
from .errors import (
    KeysManagementError,
    OnKeyChangedCallbackErrorStrategy,
    GetKeyError,
    KeyChangedError,
    KeyIsNotDefinedError,
    FetchAndSetStateFromRepoError,
    InvalidKeyStateError,
)
from .key_changed_utils import KeyChangedContext


PURPOSE_IS_NOT_USECASE_TYPE_MSG = (
    'purpose argument is not type of "SecretKeyUseCase"'
)
PURPOSE_IS_NOT_AUTHENTICATION_MSG = (
    "purpose is not SecretKeyUseCase.AUTHENTICATION"
)

DEFAULT_CALLBACK_NAME_FORMAT = "{}_callback_{}"

if TYPE_CHECKING:
    from .secret_key import KeysStore, SecretKeyValue, SecretKeyPairValues
    from .key_changed_utils import KeyChangedCallback
    from .key_changed_utils import Callbacks

logging.addLevelName(TRACE_LEVEL, TRACE_LEVEL_NAME)
logger = logging.getLogger(__name__)


class KeysManagement(object):
    def define_key(
        self,
        name: str,
        keys_store: KeysStore,
        is_stateless: bool,
        use_case: SecretKeyUseCase,
        target_data_accessible: bool,
        keep_in_cache: bool,
        on_key_changed_callback_error_strategy: OnKeyChangedCallbackErrorStrategy = None,
    ) -> KeysManagement:
        raise NotImplementedError()

    def get_key(
        self, key_name: str, purpose: SecretKeyUseCase = None
    ) -> SecretKeyValue:
        raise NotImplementedError()

    def get_encrypt_key(self, key_name: str) -> SecretKeyValue:
        return self.get_key(key_name, SecretKeyUseCase.ENCRYPTION)

    def get_decrypt_key(self, key_name: str) -> SecretKeyValue:
        return self.get_key(key_name, SecretKeyUseCase.DECRYPTION)

    def key_changed(
        self,
        key_name: str,
        old_keys: SecretKeyPairValues,
        new_keys: SecretKeyPairValues,
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

    def __init__(
        self, state_repo: StateRepoInterface, crypto_tool: CryptoTool
    ):
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
        stateless: bool,
        use_case: SecretKeyUseCase,
        target_data_accessible: bool,
        keep_in_cache: bool,
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
    ) -> SecretKeyValue:
        try:
            if not logger.isEnabledFor(logging.DEBUG):
                logger.info(GET_KEY_INFO_FORMAT.format(key_name))
            self._validate_key_name(key_name)
            key_definition: SecretKeyDefinition = self._keys_definitions[
                key_name
            ]
            purpose = (
                self._determine_get_key_purpose(purpose, key_definition)
                if purpose is None
                else purpose
            )
            logger.debug(
                GET_KEY_DEBUG_FORMAT.format(key_name, purpose.name)
            )
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
    ):
        if (
            key_definition.use_case
            == SecretKeyUseCase.ENCRYPTION_DECRYPTION
        ):
            return self._get_key_encryption_decryption_case(
                key_definition, purpose
            )
        else:
            return self._get_key_authentication_case(
                key_definition, purpose
            )

    def _update_key_definition_state(self, key_definition, purpose):
        # todo test it
        logger.log(
            TRACE_LEVEL, CLEAN_KEYS_LOG_FORMAT % key_definition.name
        )
        key_definition.clean_keys()
        key_definition.set_last_use_case(purpose)
        if self._is_clean_previous_keys(key_definition, purpose):
            logger.log(
                TRACE_LEVEL,
                CLEAN_PREV_KEYS_LOG_FORMAT % key_definition.name,
            )
            key_definition.clean_previous_keys()

    @staticmethod
    def _is_clean_previous_keys(
        key_definition: SecretKeyDefinition,
        current_purpose: SecretKeyUseCase,
    ):
        return current_purpose == SecretKeyUseCase.AUTHENTICATION or (
            current_purpose == SecretKeyUseCase.DECRYPTION
            and not key_definition.is_keep_in_cache()
        )

    def _get_key_authentication_case(
        self,
        key_definition: SecretKeyDefinition,
        purpose: SecretKeyUseCase,
    ) -> SecretKey:
        if purpose != SecretKeyUseCase.AUTHENTICATION:
            GetKeyError(
                key_name=key_definition.name,
                reason=PURPOSE_IS_NOT_AUTHENTICATION_MSG,
            )
        return SecretKey(key_definition.keys_store())

    def _get_key_encryption_decryption_case(
        self,
        key_definition: SecretKeyDefinition,
        purpose: SecretKeyUseCase,
    ) -> SecretKey:
        if purpose == SecretKeyUseCase.ENCRYPTION:
            return self._get_key_for_encryption(key_definition)
        elif purpose == SecretKeyUseCase.DECRYPTION:
            return self._get_key_for_decryption(key_definition)

    def _get_key_for_decryption(
        self, key_definition: SecretKeyDefinition
    ) -> SecretKey:
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
        return key_definition.get_previous_or_current_keys().decrypt_key

    def _get_key_for_encryption(
        self, key_definition: SecretKeyDefinition
    ) -> SecretKey:
        key_definition.set_keys_from_store()
        return key_definition.keys.encrypt_key

    def _determine_get_key_purpose(
        self,
        purpose: Optional[SecretKeyUseCase],
        key_definition: SecretKeyDefinition,
    ) -> SecretKeyUseCase:
        if purpose is not None and not isinstance(
            purpose, SecretKeyUseCase
        ):
            raise KeysManagementError(PURPOSE_IS_NOT_USECASE_TYPE_MSG)
        if key_definition.use_case not in {
            SecretKeyUseCase.ENCRYPTION_DECRYPTION,
            None,
        }:
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

    def _fetch_and_set_state_from_repo(
        self, key_definition: SecretKeyDefinition
    ) -> None:
        try:
            raw_state = self._crypto_tool.decrypt(
                self._state_repo.read_state(key_definition.name)
            )
            key_definition.set_last_use_case(
                SecretKeyUseCase.get(raw_state[STATE])
            )
            if KEY in raw_state:
                key_definition.set_previous_keys(raw_state[KEY])
        except InvalidUseCaseNameError as e:
            raise InvalidKeyStateError(key_definition.name) from e
        except Exception as e:
            raise FetchAndSetStateFromRepoError(key_definition.name) from e

    def key_changed(
        self,
        key_name: str,
        old_keys: SecretKeyPairValues,
        new_keys: SecretKeyPairValues,
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
    ):
        logger.error(
            ON_HALT_LOG_FORMAT.format(
                key_name=key_name,
                callback_name=callback_name,
                error=key_changed_context[callback_name]['error'],
            )
        )
        raise DoNothing()

    @staticmethod
    def _on_skip_strategy(
        key_name: str,
        callback_name: str,
        key_changed_context: KeyChangedContext,
    ):
        logger.error(
            ON_SKIP_LOG_FORMAT.format(
                key_name=key_name,
                callback_name=callback_name,
                error=key_changed_context[callback_name]['error'],
            )
        )

    @staticmethod
    def _on_skip_and_raise_strategy(
        key_name: str,
        callback_name: str,
        key_changed_context: KeyChangedContext,
    ):
        pass

    @staticmethod
    def _on_raise_strategy(
        key_name: str,
        callback_name: str,
        key_changed_context: KeyChangedContext,
    ):
        raise KeyChangedError(key_name, key_changed_context)

    def _create_context(
        self,
        key_definition: SecretKeyDefinition,
        old_keys: SecretKeyPairValues,
        new_keys: SecretKeyPairValues,
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
            else DEFAULT_CALLBACK_NAME_FORMAT.format(
                key_name, str(len(callbacks) + 1)
            )
        )
        callbacks[callback_name] = on_change_func

    def _validate_key_name(self, key_name: str) -> None:
        logger.info(REGISTER_ON_CHANGE_LOG_FORMAT % key_name)
        if key_name not in self._keys_definitions:
            raise KeyIsNotDefinedError(key_name)

    def save_state(self, key_name: str) -> None:
        self._validate_key_name(key_name)
        last_use_case = self._keys_definitions[
            key_name
        ].get_last_use_case()
        raw_state = {STATE: last_use_case}
        if last_use_case == SecretKeyUseCase.ENCRYPTION:
            key = self.get_decrypt_key(key_name)
            if key is not None:
                raw_state[KEY] = key
        self._write_state(key_name, raw_state)

    def _write_state(self, key_name: str, state: Dict) -> None:
        self._state_repo.write_state(
            key_name, self._crypto_tool.encrypt(state)
        )

    def save_states(self) -> None:
        for key_name, key_definition in self._keys_definitions.items():
            if key_definition.is_stated():
                self.save_state(key_name)


class DoNothing(Exception):
    pass
