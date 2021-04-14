from pytest import mark, raises, fixture
from keys_management import (
    KeysManagement,
    KeysManagementImpl,
    KeyIsNotDefinedError,
    GetKeyError,
    StateRepoInterface,
    CryptoTool,
    SecretKeyUseCase,
    OnChangeKeyDefinition,
    SecretKeyDefinitionInitError,
    KeyChangedError,
)
from keys_management.consts import KEY, STATE
from . import KeyDefForTest
from pytest_mock import MockerFixture
from unittest.mock import ANY
import logging


class TestDefineKey:
    @staticmethod
    def define_key_test(
        empty_keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        key_name = key_definition.name
        keys_store = key_definition.keys_store
        # act
        empty_keys_management.define_key(
            key_name,
            keys_store,
            key_definition.is_stateless(),
            key_definition.use_case,
            key_definition.is_target_data_accessible(),
            key_definition.is_keep_in_cache(),
        )
        # assert
        defined_key: KeysManagement = (
            empty_keys_management._keys_definitions[key_name]
        )
        assert defined_key is not None
        assert defined_key.keys_store == keys_store
        assert (
            defined_key.on_change_callbacks is not None
            and len(defined_key.on_change_callbacks) == 0
        )
        keys_store.assert_not_called()
        assert len(mocked_state_repo.method_calls) == 0
        assert len(mocked_crypto_tool.method_calls) == 0

    def test_DE_stated_not_accessible(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            DE_stated_not_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_DE_stated_accessible(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            DE_stated_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_DE_stateless_not_accessible(
        self,
        empty_keys_management: KeysManagement,
        DE_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            DE_stateless_not_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_DE_stateless_accessible(
        self,
        empty_keys_management: KeysManagement,
        DE_stateless_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            DE_stateless_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_A_stated_not_accessible(
        self,
        empty_keys_management: KeysManagement,
        A_stated_not_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            A_stated_not_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_A_stated_accessible(
        self,
        empty_keys_management: KeysManagement,
        A_stated_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            A_stated_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_A_stateless_not_accessible(
        self,
        empty_keys_management: KeysManagement,
        A_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            A_stateless_not_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_A_stateless_accessible(
        self,
        empty_keys_management: KeysManagement,
        A_stateless_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            A_stateless_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_DE_not_cached_not_accessible(
        self,
        empty_keys_management: KeysManagement,
        DE_not_cached_not_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            DE_not_cached_not_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_DE_not_cached_accessible(
        self,
        empty_keys_management: KeysManagement,
        DE_not_cached_accessible: KeyDefForTest,
        mocked_state_repo,
        mocked_crypto_tool,
    ):
        self.define_key_test(
            empty_keys_management,
            DE_not_cached_accessible,
            mocked_state_repo,
            mocked_crypto_tool,
        )

    def test_define_key_with_invalid_name__name_is_none(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                None,
                key_definition.keys_store,
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_name__name_is_empty(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                '',
                key_definition.keys_store,
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_name__name_is_not_str(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                True,
                key_definition.keys_store,
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_keys_store__is_none(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                None,
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_keys_store__is_not_callable(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                "im_str",
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_keys_store__callable_with_args(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                lambda a: a,
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_stateless(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                key_definition.keys_store,
                'aaa',
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_use_case_is_none(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                key_definition.keys_store,
                key_definition.is_stateless(),
                None,
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_use_case_is_not_use_case_type(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                key_definition.keys_store,
                key_definition.is_stateless(),
                'ENCRYPTION',
                key_definition.is_target_data_accessible(),
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_target_data_accessible(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                key_definition.keys_store,
                key_definition.is_stateless(),
                key_definition.use_case,
                "aaa",
                key_definition.is_keep_in_cache(),
            )

    def test_define_key_with_invalid_keep_in_cache(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                key_definition.keys_store,
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                "aaa",
            )

    def test_define_key_with_invalid_strategy(
        self,
        empty_keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
    ):
        key_definition = DE_stated_not_accessible
        # act
        with raises(SecretKeyDefinitionInitError):
            empty_keys_management.define_key(
                key_definition.name,
                key_definition.keys_store,
                key_definition.is_stateless(),
                key_definition.use_case,
                key_definition.is_target_data_accessible(),
                True,
                True,
            )


class TestGetKey:
    def test_key_was_not_defined__error_is_raised(
        self,
        keys_management: KeysManagement,
        not_defined_key_name: str,
        mocked_state_repo: StateRepoInterface,
    ):
        with raises(GetKeyError):
            keys_management.get_key(
                not_defined_key_name, SecretKeyUseCase.ENCRYPTION
            )

        mocked_state_repo.read_state.assert_not_called()

    def test_key_was_invalid_purpose__error_is_raised(
        self,
        keys_management: KeysManagement,
        not_defined_key_name: str,
        mocked_state_repo: StateRepoInterface,
    ):
        with raises(GetKeyError):
            keys_management.get_key(not_defined_key_name, "ofek")

        mocked_state_repo.read_state.assert_not_called()

    def test_stated_key_invalid_state(
        self,
        keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        def read_state(_key_name):
            if _key_name == stated_key_def.name:
                return {
                    STATE: "invalid_name",
                    KEY: stated_key_def.keys['decrypt'],
                }

        mocked_state_repo.read_state.side_effect = read_state
        with raises(GetKeyError):
            keys_management.get_decrypt_key(stated_key_def.name)
        mocked_state_repo.read_state.assert_called_once_with(
            stated_key_def.name
        )

    def test_stated_key_key_from_state(
        self,
        keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_from_state = 'key_from_state'

        def read_state(_key_name):
            if _key_name == stated_key_def.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_from_state,
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert (
            keys_management.get_decrypt_key(stated_key_def.name)
            == key_from_state
        )
        mocked_state_repo.read_state.assert_called_once_with(
            stated_key_def.name
        )
        stated_key_def.keys_store.assert_not_called()

    def test_stated_key_when_key_not_stored(
        self,
        keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        def read_state(_key_name):
            if _key_name == stated_key_def.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert (
            keys_management.get_decrypt_key(stated_key_def.name)
            == stated_key_def.keys['decrypt']
        )
        mocked_state_repo.read_state.assert_called_once_with(
            stated_key_def.name
        )
        stated_key_def.keys_store.assert_called_once()

    def test_stated__state_ignore_on_encrypt_purpose(
        self,
        keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        assert (
            keys_management.get_encrypt_key(stated_key_def.name)
            == stated_key_def.keys['encrypt']
        )

        mocked_state_repo.read_state.assert_not_called()

        stated_key_def.keys_store.assert_called_once()

    def test_determine_purpose_when_last_use_was_encryption(
        self,
        keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        keys_management.get_encrypt_key(stated_key_def.name)
        mocked_state_repo.reset_mock()
        assert (
            keys_management.get_key(stated_key_def.name)
            == stated_key_def.keys['decrypt']
        )
        mocked_state_repo.read_state.assert_not_called()

    def test_determine_purpose_when_last_use_was_decryption(
        self,
        keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        keys_management.get_encrypt_key(stated_key_def.name)
        mocked_state_repo.reset_mock()
        assert (
            keys_management.get_key(stated_key_def.name)
            == stated_key_def.keys['decrypt']
        )
        mocked_state_repo.read_state.assert_not_called()

    def test_determine_purpose_stateless_key(
        self,
        keys_management: KeysManagement,
        stateless_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        assert (
            keys_management.get_key(stateless_key_def.name)
            == stateless_key_def.keys['encrypt']
        )
        mocked_state_repo.read_state.assert_not_called()

    def test_determine_purpose_stated_key_when_state_is_decryption(
        self,
        keys_management: KeysManagement,
        DE_stated_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_from_state = 'key_from_state'

        def read_state(_key_name):
            if _key_name == DE_stated_accessible.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_from_state,
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert (
            keys_management.get_key(DE_stated_accessible.name)
            == DE_stated_accessible.keys['encrypt']
        )
        mocked_state_repo.read_state.assert_called_once_with(
            DE_stated_accessible.name
        )

    def test_determine_purpose_stated_key_when_state_is_encryption(
        self,
        keys_management: KeysManagement,
        DE_stated_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        def read_state(_key_name):
            if _key_name == DE_stated_accessible.name:
                return {STATE: SecretKeyUseCase.ENCRYPTION.name}

        mocked_state_repo.read_state.side_effect = read_state

        assert (
            keys_management.get_key(DE_stated_accessible.name)
            == DE_stated_accessible.keys['decrypt']
        )
        mocked_state_repo.read_state.assert_called_once_with(
            DE_stated_accessible.name
        )


class TestGetKeyEEDDE:
    @staticmethod
    def get_key_EEDDE_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = (
            key_definition.keys['encrypt'],
            key_definition.keys['decrypt'],
        )

        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_encrypt_key
        )
        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_encrypt_key
        )
        assert (
            keys_management.get_decrypt_key(key_name)
            == expected_decrypt_key
        )
        assert (
            keys_management.get_decrypt_key(key_name)
            == expected_decrypt_key
        )
        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_encrypt_key
        )

        mocked_state_repo.read_state.assert_not_called()
        expected_calls_count = (
            3 if key_definition.is_keep_in_cache() else 4
        )
        assert key_definition.keys_store.call_count == expected_calls_count

    def test_DE_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_EEDDE_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stated_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_EEDDE_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_EEDDE_scenario_test(
            keys_management, DE_stateless_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_EEDDE_scenario_test(
            keys_management, DE_stateless_accessible, mocked_state_repo
        )

    def test_DE_not_cached_not_accessible_stateless(
        self,
        keys_management: KeysManagement,
        DE_not_cached_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_EEDDE_scenario_test(
            keys_management,
            DE_not_cached_not_accessible,
            mocked_state_repo,
        )

    def test_DE_not_cached_accessible_stateless(
        self,
        keys_management: KeysManagement,
        DE_not_cached_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_EEDDE_scenario_test(
            keys_management, DE_not_cached_accessible, mocked_state_repo
        )


class TestGetKeyDDEED:
    @staticmethod
    def get_key_DDEED_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = (
            key_definition.keys['encrypt'],
            key_definition.keys['decrypt'],
        )

        def read_state(_key_name):
            if _key_name == key_definition.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_definition.keys['decrypt'],
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert (
            keys_management.get_decrypt_key(key_name)
            == expected_decrypt_key
        )
        assert (
            keys_management.get_decrypt_key(key_name)
            == expected_decrypt_key
        )
        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_encrypt_key
        )
        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_encrypt_key
        )
        assert (
            keys_management.get_decrypt_key(key_name)
            == expected_decrypt_key
        )

        if key_definition.is_stated():
            mocked_state_repo.read_state.assert_called_once_with(
                key_definition.name
            )
        else:
            mocked_state_repo.read_state.assert_not_called()

        expected_calls_count = 2
        # if is stateless the first get_decrypt_key require fetching from keystore
        if key_definition.is_stateless():
            expected_calls_count += 1
        if not key_definition.is_keep_in_cache():
            expected_calls_count += 1
        assert key_definition.keys_store.call_count == expected_calls_count

    def test_DE_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DDEED_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stated_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DDEED_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DDEED_scenario_test(
            keys_management, DE_stateless_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DDEED_scenario_test(
            keys_management, DE_stateless_accessible, mocked_state_repo
        )

    def test_DE_not_cached_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DDEED_scenario_test(
            keys_management,
            DE_not_cached_not_accessible,
            mocked_state_repo,
        )

    def test_DE_not_cached_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DDEED_scenario_test(
            keys_management, DE_not_cached_accessible, mocked_state_repo
        )


class TestGetKeyECE:
    @staticmethod
    def get_key_ECE_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = (
            key_definition.keys['encrypt'],
            key_definition.keys['decrypt'],
        )
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_encrypt_key
        )
        key_definition.set_next_as_keys(
            (expected_next_encrypt_key, expected_next_decrypt_key)
        )
        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_next_encrypt_key
        )

        mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECE_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stated_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECE_scenario_test(
            keys_management, DE_stated_accessible, mocked_state_repo
        )

    def test_DE_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECE_scenario_test(
            keys_management, DE_stateless_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECE_scenario_test(
            keys_management, DE_stateless_accessible, mocked_state_repo
        )

    def test_DE_not_cached_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECE_scenario_test(
            keys_management,
            DE_not_cached_not_accessible,
            mocked_state_repo,
        )

    def test_DE_not_cached_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECE_scenario_test(
            keys_management, DE_not_cached_accessible, mocked_state_repo
        )


class TestGetKeyECD:
    @staticmethod
    def get_key_ECD_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = (
            key_definition.keys['encrypt'],
            key_definition.keys['decrypt'],
        )
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_encrypt_key
        )
        key_definition.set_next_as_keys(
            (expected_next_encrypt_key, expected_next_decrypt_key)
        )
        after_key_changed_key = keys_management.get_decrypt_key(key_name)

        assert after_key_changed_key == expected_decrypt_key

        mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECD_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stated_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECD_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECD_scenario_test(
            keys_management, DE_stateless_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECD_scenario_test(
            keys_management, DE_stateless_accessible, mocked_state_repo
        )

    def test_DE_not_cached_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECD_scenario_test(
            keys_management,
            DE_not_cached_not_accessible,
            mocked_state_repo,
        )

    def test_DE_not_cached_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ECD_scenario_test(
            keys_management, DE_not_cached_accessible, mocked_state_repo
        )


class TestGetKeyDCE:
    @staticmethod
    def get_key_DCE_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = (
            key_definition.keys['encrypt'],
            key_definition.keys['decrypt'],
        )
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        def read_state(_key_name):
            if _key_name == key_definition.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_definition.keys['decrypt'],
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert (
            keys_management.get_decrypt_key(key_name)
            == expected_decrypt_key
        )
        key_definition.set_next_as_keys(
            (expected_next_encrypt_key, expected_next_decrypt_key)
        )
        assert (
            keys_management.get_encrypt_key(key_name)
            == expected_next_encrypt_key
        )

        if key_definition.is_stated():
            mocked_state_repo.read_state.assert_called_once_with(
                key_definition.name
            )
        else:
            mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCE_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stated_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCE_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCE_scenario_test(
            keys_management, DE_stateless_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCE_scenario_test(
            keys_management, DE_stateless_accessible, mocked_state_repo
        )

    def test_DE_not_cached_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCE_scenario_test(
            keys_management,
            DE_not_cached_not_accessible,
            mocked_state_repo,
        )

    def test_DE_not_cached_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCE_scenario_test(
            keys_management, DE_not_cached_accessible, mocked_state_repo
        )


# what you each in each test
# repository cache usage
# local cache usage according to each use-case


class TestGetKeyDCD:
    @staticmethod
    def get_key_DCD_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = (
            key_definition.keys['encrypt'],
            key_definition.keys['decrypt'],
        )
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        def read_state(_key_name):
            if _key_name == key_definition.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_definition.keys['decrypt'],
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert (
            keys_management.get_decrypt_key(key_name)
            == expected_decrypt_key
        )
        key_definition.set_next_as_keys(
            (expected_next_encrypt_key, expected_next_decrypt_key)
        )
        if key_definition.is_keep_in_cache():
            assert (
                keys_management.get_decrypt_key(key_name)
                == expected_decrypt_key
            )
        else:
            assert (
                keys_management.get_decrypt_key(key_name)
                == expected_next_decrypt_key
            )

        if key_definition.is_stated():
            mocked_state_repo.read_state.assert_called_once_with(
                key_definition.name
            )
        else:
            mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCD_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stated_accessible(
        self,
        keys_management: KeysManagement,
        DE_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCD_scenario_test(
            keys_management, DE_stated_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCD_scenario_test(
            keys_management, DE_stateless_not_accessible, mocked_state_repo
        )

    def test_DE_stateless_accessible(
        self,
        keys_management: KeysManagement,
        DE_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCD_scenario_test(
            keys_management, DE_stateless_accessible, mocked_state_repo
        )

    def test_DE_not_cached_not_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCD_scenario_test(
            keys_management,
            DE_not_cached_not_accessible,
            mocked_state_repo,
        )

    def test_DE_not_cached_accessible(
        self,
        keys_management: KeysManagement,
        DE_not_cached_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_DCD_scenario_test(
            keys_management, DE_not_cached_accessible, mocked_state_repo
        )


class TestGetKeyA:
    @staticmethod
    def get_key_AA_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_key = key_definition.keys

        assert (
            keys_management.get_key(
                key_name, SecretKeyUseCase.AUTHENTICATION
            )
            == expected_key
        )
        assert (
            keys_management.get_key(
                key_name, SecretKeyUseCase.AUTHENTICATION
            )
            == expected_key
        )
        mocked_state_repo.read_state.assert_not_called()

    @staticmethod
    def get_key_ACA_scenario_test(
        keys_management: KeysManagement,
        key_definition: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        key_name = key_definition.name
        expected_key = key_definition.keys
        expected_next_key = "new_" + expected_key

        assert (
            keys_management.get_key(
                key_name, SecretKeyUseCase.AUTHENTICATION
            )
            == expected_key
        )
        key_definition.set_next_as_keys(expected_next_key)
        assert (
            keys_management.get_key(
                key_name, SecretKeyUseCase.AUTHENTICATION
            )
            == expected_next_key
        )
        mocked_state_repo.read_state.assert_not_called()

    def test_get_key_AA_scenario_A_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        A_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_AA_scenario_test(
            keys_management, A_stated_not_accessible, mocked_state_repo
        )

    def test_get_key_AA_scenario_A_stated_accessible(
        self,
        keys_management: KeysManagement,
        A_stated_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_AA_scenario_test(
            keys_management, A_stated_accessible, mocked_state_repo
        )

    def test_get_key_AA_scenario_A_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        A_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_AA_scenario_test(
            keys_management, A_stateless_not_accessible, mocked_state_repo
        )

    def test_get_key_AA_scenario_A_stateless_accessible(
        self,
        keys_management: KeysManagement,
        A_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_AA_scenario_test(
            keys_management, A_stateless_accessible, mocked_state_repo
        )

    def test_get_key_ACA_scenario_A_stated_not_accessible(
        self,
        keys_management: KeysManagement,
        A_stated_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ACA_scenario_test(
            keys_management, A_stated_not_accessible, mocked_state_repo
        )

    def test_get_key_ACA_scenario_A_stated_accessible(
        self,
        keys_management: KeysManagement,
        A_stated_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ACA_scenario_test(
            keys_management, A_stated_accessible, mocked_state_repo
        )

    def test_get_key_ACA_scenario_A_stateless_not_accessible(
        self,
        keys_management: KeysManagement,
        A_stateless_not_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ACA_scenario_test(
            keys_management, A_stateless_not_accessible, mocked_state_repo
        )

    def test_get_key_ACA_scenario_A_stateless_accessible(
        self,
        keys_management: KeysManagement,
        A_stateless_accessible: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
    ):
        self.get_key_ACA_scenario_test(
            keys_management, A_stateless_accessible, mocked_state_repo
        )


class TestKeyManagementImpl:
    def test_on_change_invalid_key(
        self, keys_management: KeysManagement, not_defined_key_name: str
    ):
        with raises(KeyIsNotDefinedError):
            keys_management.register_on_change(
                not_defined_key_name, lambda n, o: n
            )

    def test_on_change__with_key_changed(
        self,
        keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        mocker: MockerFixture,
    ):
        first_on_change_mock = mocker.MagicMock()
        second_on_change_mock = mocker.MagicMock()
        third_on_change_mock = mocker.MagicMock()

        keys_management.register_on_change(
            stated_key_def.name, first_on_change_mock
        )
        keys_management.register_on_change(
            stated_key_def.name, second_on_change_mock
        )
        keys_management.register_on_change(
            stated_key_def.name, third_on_change_mock
        )

        old_key = "old_key"
        new_key = "new_key"

        keys_management.key_changed(stated_key_def.name, old_key, new_key)

        first_on_change_mock.assert_called_once_with(old_key, new_key, ANY)
        second_on_change_mock.assert_called_once_with(
            old_key, new_key, ANY
        )
        third_on_change_mock.assert_called_once_with(old_key, new_key, ANY)

    def test_key_changed__halt_strategy(
        self,
        keys_management: KeysManagement,
        halt_error_strategy_key_def: KeyDefForTest,
        mocker: MockerFixture,
    ):
        def raise_error(a, b, c):
            raise RuntimeError('error')

        first_on_change_mock = mocker.MagicMock()
        second_on_change_mock = mocker.MagicMock(side_effect=raise_error)
        third_on_change_mock = mocker.MagicMock()

        keys_management.register_on_change(
            halt_error_strategy_key_def.name, first_on_change_mock
        )
        keys_management.register_on_change(
            halt_error_strategy_key_def.name, second_on_change_mock
        )
        keys_management.register_on_change(
            halt_error_strategy_key_def.name, third_on_change_mock
        )

        old_key = "old_key"
        new_key = "new_key"

        keys_management.key_changed(
            halt_error_strategy_key_def.name, old_key, new_key
        )

        first_on_change_mock.assert_called_once_with(old_key, new_key, ANY)
        second_on_change_mock.assert_called_once_with(
            old_key, new_key, ANY
        )
        third_on_change_mock.assert_not_called()

    def test_key_changed__skip_strategy(
        self,
        keys_management: KeysManagement,
        skip_error_strategy_key_def: KeyDefForTest,
        mocker: MockerFixture,
    ):
        def raise_error(a, b, c):
            raise RuntimeError('error')

        first_on_change_mock = mocker.MagicMock()
        second_on_change_mock = mocker.MagicMock(side_effect=raise_error)
        third_on_change_mock = mocker.MagicMock()

        keys_management.register_on_change(
            skip_error_strategy_key_def.name, first_on_change_mock
        )
        keys_management.register_on_change(
            skip_error_strategy_key_def.name, second_on_change_mock
        )
        keys_management.register_on_change(
            skip_error_strategy_key_def.name, third_on_change_mock
        )

        old_key = "old_key"
        new_key = "new_key"

        keys_management.key_changed(
            skip_error_strategy_key_def.name, old_key, new_key
        )

        first_on_change_mock.assert_called_once_with(old_key, new_key, ANY)
        second_on_change_mock.assert_called_once_with(
            old_key, new_key, ANY
        )
        third_on_change_mock.assert_called_once_with(old_key, new_key, ANY)

    def test_key_changed__skip_and_raise_strategy(
        self,
        keys_management: KeysManagement,
        skip_raise_error_strategy_key_def: KeyDefForTest,
        mocker: MockerFixture,
    ):
        def raise_error(a, b, c):
            raise RuntimeError('error')

        first_on_change_mock = mocker.MagicMock()
        second_on_change_mock = mocker.MagicMock(side_effect=raise_error)
        third_on_change_mock = mocker.MagicMock()

        keys_management.register_on_change(
            skip_raise_error_strategy_key_def.name, first_on_change_mock
        )
        keys_management.register_on_change(
            skip_raise_error_strategy_key_def.name, second_on_change_mock
        )
        keys_management.register_on_change(
            skip_raise_error_strategy_key_def.name, third_on_change_mock
        )

        old_key = "old_key"
        new_key = "new_key"

        with raises(KeyChangedError):
            keys_management.key_changed(
                skip_raise_error_strategy_key_def.name, old_key, new_key
            )

        first_on_change_mock.assert_called_once_with(old_key, new_key, ANY)
        second_on_change_mock.assert_called_once_with(
            old_key, new_key, ANY
        )
        third_on_change_mock.assert_called_once_with(old_key, new_key, ANY)

    def test_key_changed__raise_strategy(
        self,
        keys_management: KeysManagement,
        raise_error_strategy_key_def: KeyDefForTest,
        mocker: MockerFixture,
    ):
        def raise_error(a, b, c):
            raise RuntimeError('error')

        first_on_change_mock = mocker.MagicMock()
        second_on_change_mock = mocker.MagicMock(side_effect=raise_error)
        third_on_change_mock = mocker.MagicMock()

        keys_management.register_on_change(
            raise_error_strategy_key_def.name, first_on_change_mock
        )
        keys_management.register_on_change(
            raise_error_strategy_key_def.name, second_on_change_mock
        )
        keys_management.register_on_change(
            raise_error_strategy_key_def.name, third_on_change_mock
        )

        old_key = "old_key"
        new_key = "new_key"

        with raises(KeyChangedError):
            keys_management.key_changed(
                raise_error_strategy_key_def.name, old_key, new_key
            )

        first_on_change_mock.assert_called_once_with(old_key, new_key, ANY)
        second_on_change_mock.assert_called_once_with(
            old_key, new_key, ANY
        )
        third_on_change_mock.assert_not_called()

    def test_save_states_when_last_stated_key_use_is_encryption(
        self,
        empty_keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        stateless_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
        mocked_crypto_tool: CryptoTool,
    ):

        for key_def in [stateless_key_def, stated_key_def]:
            empty_keys_management.define_key(
                key_def.name,
                key_def.keys_store,
                key_def.is_stateless(),
                key_def.use_case,
                key_def.is_target_data_accessible(),
                key_def.is_keep_in_cache(),
                key_def.on_key_changed_callback_error_strategy,
            )

        # arrange
        mocked_crypto_tool.decrypt.side_effect = lambda data: data
        mocked_crypto_tool.encrypt.side_effect = lambda data: data

        empty_keys_management.get_encrypt_key(stated_key_def.name)
        empty_keys_management.get_key(stateless_key_def.name)

        encryption_state = {
            STATE: SecretKeyUseCase.ENCRYPTION,
            KEY: stated_key_def.keys['decrypt'],
        }

        # act
        empty_keys_management.save_states()

        # assert
        mocked_state_repo.write_state.assert_called_once_with(
            stated_key_def.name, encryption_state
        )
        mocked_crypto_tool.encrypt.assert_called_once_with(
            encryption_state
        )

    def test_save_states_when_last_stated_key_use_is_decryption(
        self,
        empty_keys_management: KeysManagement,
        stated_key_def: KeyDefForTest,
        stateless_key_def: KeyDefForTest,
        mocked_state_repo: StateRepoInterface,
        mocked_crypto_tool: CryptoTool,
    ):

        for key_def in [stateless_key_def, stated_key_def]:
            empty_keys_management.define_key(
                key_def.name,
                key_def.keys_store,
                key_def.is_stateless(),
                key_def.use_case,
                key_def.is_target_data_accessible(),
                key_def.is_keep_in_cache(),
                key_def.on_key_changed_callback_error_strategy,
            )

        # arrange
        mocked_crypto_tool.decrypt.side_effect = lambda data: data
        mocked_crypto_tool.encrypt.side_effect = lambda data: data

        def read_state(key_name):
            if key_name == stated_key_def.name:
                return {STATE: SecretKeyUseCase.ENCRYPTION.name}

        mocked_state_repo.read_state.side_effect = read_state

        empty_keys_management.get_decrypt_key(stated_key_def.name)
        empty_keys_management.get_key(stateless_key_def.name)

        decryption_state = {STATE: SecretKeyUseCase.DECRYPTION}

        # act
        empty_keys_management.save_states()

        # assert
        mocked_state_repo.write_state.assert_called_once_with(
            stated_key_def.name, decryption_state
        )
        mocked_crypto_tool.encrypt.assert_called_once_with(
            decryption_state
        )


@fixture
def empty_keys_management(
    mocked_state_repo: StateRepoInterface, mocked_crypto_tool: CryptoTool
) -> KeysManagement:
    mocked_crypto_tool.decrypt.side_effect = lambda data: data
    mocked_crypto_tool.encrypt.side_effect = lambda data: data
    return KeysManagementImpl(mocked_state_repo, mocked_crypto_tool)
