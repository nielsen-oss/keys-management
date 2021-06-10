from __future__ import annotations
import logging
from typing import TYPE_CHECKING, Callable, Dict, Optional, Union, cast
from .consts import KEY, STATE, TRACE_LEVEL, TRACE_LEVEL_NAME
from .dependecies import CryptoTool, StateRepoInterface
from .errors import (
    FetchAndSetStateFromRepoError,
    GetKeyError,
    InvalidKeyStateError,
    KeyChangedError,
    KeyIsNotDefinedError,
    OnKeyChangedCallbackErrorStrategy,
)
from .key_changed_utils import KeyChangedContext
from .log_messages_consts import (
    CLEAN_KEYS_LOG_FORMAT,
    CLEAN_PREV_KEYS_LOG_FORMAT,
    DEFINE_KEY_LOG_FORMAT,
    GET_KEY_DEBUG_FORMAT,
    GET_KEY_INFO_FORMAT,
    KEY_CHANGED_DEBUG_FORMAT,
    KEY_CHANGED_INFO_FORMAT,
    ON_HALT_LOG_FORMAT,
    ON_SKIP_LOG_FORMAT,
    REGISTER_ON_CHANGE_LOG_FORMAT,
    RV_KEY_LOG_FORMAT,
    SUCCESS_DEFINE_KEY_LOG_FORMAT,
)
from .secret_key import (
    InvalidFlowNameError,
    SecretKeyDefinition,
    SecretKeyFlow,
    SecretKeyPair,
    SecretKeyUseCase,
    SecretKeyValue,
)

if TYPE_CHECKING:
    from .key_changed_utils import KeyChangedCallback
    from .secret_key import KeysStore, StrOrBytes, StrOrBytesPair

logging.addLevelName(TRACE_LEVEL, TRACE_LEVEL_NAME)
logger = logging.getLogger(__name__)

FLOW_IS_NOT_FLOW_TYPE_MSG = 'flow argument is not type of "SecretKeyFlow"'
FLOW_IS_NOT_DEFAULT_MSG = "flow is not SecretKeyFlow.DEFAULT or aliases"
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
        keep_in_cache: bool,
        on_key_changed_callback_error_strategy: OnKeyChangedCallbackErrorStrategy = None,
    ) -> KeysManagement:
        raise NotImplementedError()

    def get_key(self, key_name: str, flow: SecretKeyFlow) -> StrOrBytes:
        raise NotImplementedError()

    def get_forward_path_key(self, key_name: str) -> StrOrBytes:
        return self.get_key(key_name, SecretKeyFlow.FORWARD_PATH)

    def get_encrypt_key(self, key_name: str) -> StrOrBytes:
        return self.get_forward_path_key(key_name)

    def get_back_path_key(self, key_name: str) -> StrOrBytes:
        return self.get_key(key_name, SecretKeyFlow.BACK_PATH)

    def get_decrypt_key(self, key_name: str) -> StrOrBytes:
        return self.get_back_path_key(key_name)

    def key_changed(
        self,
        key_name: str,
        old_keys: Union[StrOrBytes, StrOrBytesPair],
        new_keys: Union[StrOrBytes, StrOrBytesPair],
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
        self,
        state_repo: Optional[StateRepoInterface] = None,
        crypto_tool: Optional[CryptoTool] = None,
    ):
        self._state_repo = (
            state_repo if state_repo is not None else StateRepoInterface()
        )
        self._crypto_tool = crypto_tool if crypto_tool is not None else CryptoTool()
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
            keep_in_cache=keep_in_cache,
            on_key_changed_callback_error_strategy=on_key_changed_callback_error_strategy,
        )
        logger.debug(SUCCESS_DEFINE_KEY_LOG_FORMAT % str(key_definition))
        self._keys_definitions[name] = key_definition
        return self

    def get_key(self, key_name: str, flow: SecretKeyFlow = None) -> StrOrBytes:
        try:
            if not logger.isEnabledFor(logging.DEBUG):
                logger.info(GET_KEY_INFO_FORMAT.format(key_name))
            self._validate_key_name(key_name)
            key_definition = self._keys_definitions[key_name]
            flow = self._determine_flow(key_definition) if flow is None else flow
            logger.debug(GET_KEY_DEBUG_FORMAT.format(key_name, flow.name))
            rv_key = self._get_key_by_flow(key_definition, flow)
            logger.debug(RV_KEY_LOG_FORMAT, str(rv_key))
            self._update_key_definition_state(key_definition, flow)
            return rv_key.get_value()
        except GetKeyError as e:
            raise e
        except Exception as e:
            raise GetKeyError(key_name) from e

    def _validate_key_name(self, key_name: str) -> None:
        logger.info(REGISTER_ON_CHANGE_LOG_FORMAT % key_name)
        if key_name not in self._keys_definitions:
            raise KeyIsNotDefinedError(key_name)

    def _determine_flow(self, key_definition: SecretKeyDefinition) -> SecretKeyFlow:
        if key_definition.use_case not in {SecretKeyUseCase.ROUND_TRIP, None}:
            return SecretKeyFlow.DEFAULT
        else:
            return self.__determine_flow_by_previous_flow(key_definition)

    def __determine_flow_by_previous_flow(
        self, key_definition: SecretKeyDefinition
    ) -> SecretKeyFlow:
        prev_flow = self.__get_previous_flow(key_definition)
        if prev_flow == SecretKeyFlow.FORWARD_PATH:
            return SecretKeyFlow.BACK_PATH
        else:
            return SecretKeyFlow.FORWARD_PATH

    def __get_previous_flow(
        self, key_definition: SecretKeyDefinition
    ) -> Optional[SecretKeyFlow]:
        prev_flow = key_definition.get_last_flow()
        if prev_flow is None and key_definition.is_stated():
            self._fetch_and_set_state_from_repo(key_definition)
            prev_flow = key_definition.get_last_flow()
        return prev_flow

    def _fetch_and_set_state_from_repo(
        self, key_definition: SecretKeyDefinition
    ) -> None:
        try:
            raw_state = self._crypto_tool.decrypt(
                self._state_repo.read_state(key_definition.name)
            )
            key_definition.set_last_flow(SecretKeyFlow.get(raw_state[STATE]))
            if KEY in raw_state:
                key_definition.set_previous_keys(raw_state[KEY])
        except InvalidFlowNameError as e:
            raise InvalidKeyStateError(key_definition.name) from e
        except Exception as e:
            raise FetchAndSetStateFromRepoError(key_definition.name) from e

    def _get_key_by_flow(
        self,
        key_definition: SecretKeyDefinition,
        flow: SecretKeyFlow,
    ) -> SecretKeyValue:
        if key_definition.use_case == SecretKeyUseCase.ROUND_TRIP:
            return self._get_key_round_trip_case(key_definition, flow)
        else:
            return self._get_key_one_way_case(key_definition, flow)

    def _get_key_round_trip_case(
        self,
        key_definition: SecretKeyDefinition,
        flow: SecretKeyFlow,
    ) -> SecretKeyValue:
        if flow == SecretKeyFlow.FORWARD_PATH:
            return self._get_key_for_forward(key_definition)
        else:  # flow == SecretKeyFlow.BACK_PATH:
            return self._get_key_for_back_path(key_definition)

    def _get_key_for_forward(
        self, key_definition: SecretKeyDefinition
    ) -> SecretKeyValue:
        key_definition.set_keys_from_store()
        return key_definition.keys.forward_key  # type: ignore[union-attr]

    def _get_key_for_back_path(
        self, key_definition: SecretKeyDefinition
    ) -> SecretKeyValue:
        if not key_definition.has_keys():
            if key_definition.get_last_flow() is None and key_definition.is_stated():
                self._fetch_and_set_state_from_repo(key_definition)
                if not key_definition.has_keys():
                    key_definition.set_keys_from_store()
            else:
                key_definition.set_keys_from_store()
        return key_definition.get_previous_or_current_keys().back_path_key  # type: ignore[union-attr]

    def _get_key_one_way_case(
        self,
        key_definition: SecretKeyDefinition,
        flow: SecretKeyFlow,
    ) -> SecretKeyValue:
        if flow != SecretKeyFlow.DEFAULT:
            GetKeyError(
                key_name=key_definition.name,
                reason=FLOW_IS_NOT_DEFAULT_MSG,
            )
        return SecretKeyValue(cast(Union[str, bytes], key_definition.keys_store()))

    def _update_key_definition_state(
        self, key_definition: SecretKeyDefinition, flow: SecretKeyFlow
    ) -> None:
        # todo test it
        logger.log(TRACE_LEVEL, CLEAN_KEYS_LOG_FORMAT % key_definition.name)
        key_definition.clean_keys()
        key_definition.set_last_flow(flow)
        if self._is_clean_previous_keys(key_definition, flow):
            logger.log(TRACE_LEVEL, CLEAN_PREV_KEYS_LOG_FORMAT % key_definition.name)
            key_definition.clean_previous_keys()

    @staticmethod
    def _is_clean_previous_keys(
        key_definition: SecretKeyDefinition,
        current_flow: SecretKeyFlow,
    ) -> bool:
        return current_flow == SecretKeyFlow.DEFAULT or (
            current_flow == SecretKeyFlow.BACK_PATH
            and not key_definition.is_keep_in_cache()
        )

    def key_changed(
        self,
        key_name: str,
        old_keys: Union[StrOrBytes, StrOrBytesPair] = None,
        new_keys: Union[StrOrBytes, StrOrBytesPair] = None,
    ) -> None:
        try:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    KEY_CHANGED_DEBUG_FORMAT.format(
                        key_name,
                        str(SecretKeyPair(old_keys)) if old_keys is not None else None,
                        str(SecretKeyPair(new_keys)) if new_keys is not None else None,
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
        old_keys: Optional[Union[StrOrBytes, StrOrBytesPair]],
        new_keys: Optional[Union[StrOrBytes, StrOrBytesPair]],
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

    def save_state(self, key_name: str) -> None:
        self._validate_key_name(key_name)
        last_flow = self._keys_definitions[key_name].get_last_flow()
        raw_state = {STATE: last_flow}
        if last_flow == SecretKeyFlow.FORWARD_PATH:
            key = self.get_back_path_key(key_name)
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
