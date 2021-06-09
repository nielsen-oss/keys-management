from __future__ import annotations
from typing import TYPE_CHECKING, Callable, List, Tuple
from pytest import fixture
from pytest_mock import MockerFixture
from keys_management import (
    CryptoTool,
    KeysManagement,
    OnKeyChangedCallbackErrorStrategy,
    StateRepoInterface,
)
from keys_management.secret_key import SecretKeyUseCase
from . import KeyDefForTest

if TYPE_CHECKING:
    from keys_management.secret_key import KeysStore

    KeyDefinitionFactory = Callable[..., KeyDefForTest]


@fixture
def mocked_state_repo(mocker: MockerFixture) -> StateRepoInterface:
    return mocker.patch("keys_management.StateRepoInterface", spec_set=True)


@fixture
def mocked_crypto_tool(mocker: MockerFixture) -> CryptoTool:
    return mocker.patch("keys_management.CryptoTool", create=True, spec_set=True)


@fixture
def stateless_key_name() -> str:
    return "stateless_key_name"


@fixture
def stated_key_name() -> str:
    return "stated_key_name"


@fixture
def stateless_key() -> str:
    return "stateless_key"


@fixture
def stated_key() -> str:
    return "stated_key"


@fixture
def keys_management(
    empty_keys_management: KeysManagement,
    all_key_definitions: List[KeyDefForTest],
) -> KeysManagement:
    for key_def in all_key_definitions:
        empty_keys_management.define_key(
            key_def.name,
            key_def.keys_store,
            key_def.use_case,
            key_def.is_stateless(),
            key_def.is_keep_in_cache(),
            key_def.on_key_changed_callback_error_strategy,
        )
    return empty_keys_management


@fixture
def not_defined_key_name() -> str:
    return "not_defined_key_name"


@fixture
def key_name() -> str:
    return "key_name"


@fixture
def keys_store(mocker: MockerFixture, stated_key: str) -> KeysStore:
    return mocker.MagicMock(return_value=stated_key)


@fixture
def key_def(key_name: str, stated_key: str) -> KeyDefForTest:
    return KeyDefForTest(
        name=key_name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ROUND_TRIP,
    )


@fixture
def key_definition_factory() -> KeyDefinitionFactory:
    return KeyDefForTest


def convert_key_name_to_values(name: str) -> Tuple:
    return "forward_" + name + "_val", "back_" + name + "_val"


def convert_key_name_to_value(name: str) -> str:
    return name + "_val"


@fixture
def RT_stated(key_definition_factory: KeyDefinitionFactory) -> KeyDefForTest:
    key_name = "RT_stated"
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=False,
        keep_in_cache=True,
    )


@fixture
def RT_stateless(
    key_definition_factory: KeyDefinitionFactory,
) -> KeyDefForTest:
    key_name = "RT_stateless"
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=True,
        keep_in_cache=True,
    )


@fixture
def RT_not_cached(
    key_definition_factory: KeyDefinitionFactory,
) -> KeyDefForTest:
    key_name = "RT_not_cached"
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=True,
        keep_in_cache=False,
    )


@fixture
def OWT_stated(
    key_definition_factory: KeyDefinitionFactory,
) -> KeyDefForTest:
    key_name = "OWT_stated"
    key_val = convert_key_name_to_value(key_name)
    return key_definition_factory(
        name=key_name,
        keys=key_val,
        use_case=SecretKeyUseCase.ONE_WAY_TRIP,
        stateless=False,
        keep_in_cache=True,
        key_as_single=True,
    )


@fixture
def OWT_stateless(
    key_definition_factory: KeyDefinitionFactory,
) -> KeyDefForTest:
    key_name = "OWT_stateless"
    key_val = convert_key_name_to_value(key_name)
    return key_definition_factory(
        name=key_name,
        keys=key_val,
        use_case=SecretKeyUseCase.ONE_WAY_TRIP,
        stateless=True,
        keep_in_cache=True,
        key_as_single=True,
    )


@fixture
def stateless_key_def(stateless_key_name: str, stateless_key: str) -> KeyDefForTest:
    return KeyDefForTest(
        name=stateless_key_name,
        keys=stateless_key,
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=True,
    )


@fixture
def stated_key_def(stated_key_name: str, stated_key: str) -> KeyDefForTest:
    return KeyDefForTest(
        name=stated_key_name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=False,
    )


@fixture
def halt_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
) -> KeyDefForTest:
    name = "HALT_KEY_DEF"
    return KeyDefForTest(
        name=name,
        keys=stateless_key,
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.HALT,
    )


@fixture
def skip_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
) -> KeyDefForTest:
    name = "SKIP_KEY_DEF"
    return KeyDefForTest(
        name=name,
        keys=stateless_key,
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.SKIP,
    )


@fixture
def skip_raise_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
) -> KeyDefForTest:
    name = "SKIP_AND_RAISE_KEY_DEF"
    return KeyDefForTest(
        name=name,
        keys=stateless_key,
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.SKIP_AND_RAISE,
    )


@fixture
def raise_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
) -> KeyDefForTest:
    name = "RAISE_KEY_DEF"
    return KeyDefForTest(
        name=name,
        keys=stateless_key,
        use_case=SecretKeyUseCase.ROUND_TRIP,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.RAISE_IMMEDIATELY,
    )


@fixture
def all_key_definitions(
    RT_stated,
    RT_stateless,
    RT_not_cached,
    OWT_stated: KeyDefForTest,
    OWT_stateless,
    stateless_key_def: KeyDefForTest,
    stated_key_def: KeyDefForTest,
    halt_error_strategy_key_def: KeyDefForTest,
    skip_error_strategy_key_def: KeyDefForTest,
    skip_raise_error_strategy_key_def: KeyDefForTest,
    raise_error_strategy_key_def: KeyDefForTest,
) -> List[KeyDefForTest]:
    return [
        RT_stated,
        RT_stateless,
        RT_not_cached,
        OWT_stated,
        OWT_stateless,
        stateless_key_def,
        stated_key_def,
        halt_error_strategy_key_def,
        skip_error_strategy_key_def,
        skip_raise_error_strategy_key_def,
        raise_error_strategy_key_def,
    ]
