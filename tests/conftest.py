from __future__ import annotations
from typing import List, Tuple, TYPE_CHECKING
from pytest import fixture
from pytest_mock import MockerFixture
from keys_management import (
    KeysManagement,
    StateRepoInterface,
    CryptoTool,
    OnKeyChangedCallbackErrorStrategy,
)
from keys_management.secret_key import SecretKeyUseCase
from . import KeyDefForTest

if TYPE_CHECKING:
    from keys_management.secret_key import KeysStore


@fixture
def mocked_state_repo(mocker: MockerFixture) -> StateRepoInterface:
    return mocker.patch(
        'keys_management.StateRepoInterface', spec_set=True
    )


@fixture
def mocked_crypto_tool(mocker: MockerFixture) -> CryptoTool:
    return mocker.patch(
        'keys_management.CryptoTool', create=True, spec_set=True
    )


@fixture
def stateless_key_name() -> str:
    return 'stateless_key_name'


@fixture
def stated_key_name() -> str:
    return 'stated_key_name'


@fixture
def stateless_key():
    return 'stateless_key'


@fixture
def stated_key():
    return 'stated_key'


@fixture
def keys_management(
    empty_keys_management: KeysManagement,
    all_key_definitions: List[KeyDefForTest],
):
    for key_def in all_key_definitions:
        empty_keys_management.define_key(
            key_def.name,
            key_def.keys_store,
            key_def.is_stateless(),
            key_def.use_case,
            key_def.is_target_data_accessible(),
            key_def.is_keep_in_cache(),
            key_def.on_key_changed_callback_error_strategy,
        )
    return empty_keys_management


@fixture
def not_defined_key_name() -> str:
    return 'not_defined_key_name'


@fixture
def key_name() -> str:
    return 'key_name'


@fixture
def keys_store(mocker: MockerFixture, stated_key) -> KeysStore:
    return mocker.MagicMock(return_value=stated_key)


@fixture
def key_def(key_name: str, stated_key: str) -> KeyDefForTest:
    return KeyDefForTest(
        name=key_name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
    )


@fixture
def key_definition_factory():
    return KeyDefForTest


def convert_key_name_to_values(name: str) -> Tuple:
    return "encrypt_" + name + "_val", "decrypt_" + name + "_val"


def convert_key_name_to_value(name: str) -> str:
    return name + "_val"


@fixture
def DE_stated_not_accessible(key_definition_factory) -> KeyDefForTest:
    key_name = 'DE_stated_not_accessible'
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=False,
        target_data_accessible=False,
        keep_in_cache=True,
    )


@fixture
def DE_stated_accessible(key_definition_factory):
    key_name = 'DE_stated_accessible'
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=False,
        target_data_accessible=True,
        keep_in_cache=True,
    )


@fixture
def DE_stateless_not_accessible(key_definition_factory):
    key_name = 'DE_stateless_not_accessible'
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=True,
        target_data_accessible=False,
        keep_in_cache=True,
    )


@fixture
def DE_stateless_accessible(key_definition_factory):
    key_name = 'DE_stateless_accessible'
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=True,
        target_data_accessible=True,
        keep_in_cache=True,
    )


@fixture
def DE_not_cached_accessible(key_definition_factory):
    key_name = 'DE_not_cached_accessible'
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=True,
        target_data_accessible=True,
        keep_in_cache=False,
    )


@fixture
def DE_not_cached_not_accessible(key_definition_factory):
    key_name = 'DE_not_cached_not_accessible'
    return key_definition_factory(
        name=key_name,
        keys=convert_key_name_to_values(key_name),
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=True,
        target_data_accessible=True,
        keep_in_cache=False,
    )


@fixture
def A_stated_not_accessible(key_definition_factory):
    key_name = 'A_stated_not_accessible'
    key_val = convert_key_name_to_value(key_name)
    return key_definition_factory(
        name=key_name,
        keys=key_val,
        use_case=SecretKeyUseCase.AUTHENTICATION,
        stateless=False,
        target_data_accessible=False,
        keep_in_cache=True,
        key_as_single=True,
    )


@fixture
def A_stated_accessible(key_definition_factory):
    key_name = 'A_stated_accessible'
    key_val = convert_key_name_to_value(key_name)
    return key_definition_factory(
        name=key_name,
        keys=key_val,
        use_case=SecretKeyUseCase.AUTHENTICATION,
        stateless=False,
        target_data_accessible=True,
        keep_in_cache=True,
        key_as_single=True,
    )


@fixture
def A_stateless_not_accessible(key_definition_factory):
    key_name = 'A_stateless_not_accessible'
    key_val = convert_key_name_to_value(key_name)
    return key_definition_factory(
        name=key_name,
        keys=key_val,
        use_case=SecretKeyUseCase.AUTHENTICATION,
        stateless=True,
        target_data_accessible=False,
        keep_in_cache=True,
        key_as_single=True,
    )


@fixture
def A_stateless_accessible(key_definition_factory):
    key_name = 'A_stateless_accessible'
    key_val = convert_key_name_to_value(key_name)
    return KeyDefForTest(
        name=key_name,
        keys=key_val,
        use_case=SecretKeyUseCase.AUTHENTICATION,
        stateless=True,
        target_data_accessible=True,
        keep_in_cache=True,
        key_as_single=True,
    )


@fixture
def stateless_key_def(
    stateless_key_name: str, stateless_key: str
) -> KeyDefForTest:
    return KeyDefForTest(
        name=stateless_key_name,
        keys=stateless_key,
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=True,
    )


@fixture
def stated_key_def(stated_key_name, stated_key) -> KeyDefForTest:
    return KeyDefForTest(
        name=stated_key_name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=False,
    )


@fixture
def halt_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
):
    name = 'HALT_KEY_DEF'
    return KeyDefForTest(
        name=name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.HALT,
    )


@fixture
def skip_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
):
    name = 'SKIP_KEY_DEF'
    return KeyDefForTest(
        name=name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.SKIP,
    )


@fixture
def skip_raise_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
):
    name = 'SKIP_AND_RAISE_KEY_DEF'
    return KeyDefForTest(
        name=name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.SKIP_AND_RAISE,
    )


@fixture
def raise_error_strategy_key_def(
    stateless_key_name: str, stateless_key: str
):
    name = 'RAISE_KEY_DEF'
    return KeyDefForTest(
        name=name,
        keys=stated_key,
        use_case=SecretKeyUseCase.ENCRYPTION_DECRYPTION,
        stateless=False,
        on_key_changed_callback_error_strategy=OnKeyChangedCallbackErrorStrategy.RAISE_IMMEDIATELY,
    )


@fixture
def all_key_definitions(
    DE_stated_not_accessible,
    DE_stated_accessible,
    DE_stateless_not_accessible,
    DE_stateless_accessible,
    DE_not_cached_not_accessible,
    DE_not_cached_accessible,
    A_stated_not_accessible,
    A_stated_accessible,
    A_stateless_not_accessible,
    A_stateless_accessible,
    stateless_key_def,
    stated_key_def,
    halt_error_strategy_key_def,
    skip_error_strategy_key_def,
    skip_raise_error_strategy_key_def,
    raise_error_strategy_key_def,
) -> List[KeyDefForTest]:
    return [
        DE_stated_not_accessible,
        DE_stated_accessible,
        DE_stateless_not_accessible,
        DE_stateless_accessible,
        DE_not_cached_not_accessible,
        DE_not_cached_accessible,
        A_stated_not_accessible,
        A_stated_accessible,
        A_stateless_not_accessible,
        A_stateless_accessible,
        stateless_key_def,
        stated_key_def,
        halt_error_strategy_key_def,
        skip_error_strategy_key_def,
        skip_raise_error_strategy_key_def,
        raise_error_strategy_key_def,
    ]
