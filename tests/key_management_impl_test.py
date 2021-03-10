from pytest import mark, raises, fixture
from keys_management import KeysManagement, KeyIsNotDefinedError, StateRepoInterface, CryptoTool
from keys_management.secret_key import SecretKeyUseCase
from keys_management.impl import KeysManagementImpl, InvalidKeyStateError
from keys_management.consts import KEY, STATE
from . import KeyDefForTest


class TestDefineKey:
    @staticmethod
    def define_key_test(empty_keys_management: KeysManagement, key_definition: KeyDefForTest, mocked_state_repo,
                        mocked_crypto_tool):
        key_name = key_definition.name
        keys_store = key_definition.keys_store
        # act
        empty_keys_management.define_key(key_name, keys_store, key_definition.is_stateless(), key_definition.use_case,
                                         key_definition.is_target_data_accessible(), key_definition.is_keep_in_cache())
        # assert
        defined_key: KeysManagement = empty_keys_management._keys_definitions[key_name]
        assert defined_key is not None
        assert defined_key.keys_store == keys_store
        assert defined_key.on_change_callbacks is not None and len(defined_key.on_change_callbacks) == 0
        keys_store.assert_not_called()
        assert len(mocked_state_repo.method_calls) == 0
        assert len(mocked_crypto_tool.method_calls) == 0

    def test_DE_stated_not_accessible(self, empty_keys_management: KeysManagement,
                                      DE_stated_not_accessible: KeyDefForTest, mocked_state_repo, mocked_crypto_tool):
        self.define_key_test(empty_keys_management, DE_stated_not_accessible, mocked_state_repo,
                             mocked_crypto_tool)

    def test_DE_stated_accessible(self, empty_keys_management: KeysManagement,
                                  DE_stated_accessible: KeyDefForTest, mocked_state_repo, mocked_crypto_tool):
        self.define_key_test(empty_keys_management, DE_stated_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_DE_stateless_not_accessible(self, empty_keys_management: KeysManagement,
                                         DE_stateless_not_accessible: KeyDefForTest, mocked_state_repo,
                                         mocked_crypto_tool):
        self.define_key_test(empty_keys_management, DE_stateless_not_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_DE_stateless_accessible(self, empty_keys_management: KeysManagement,
                                     DE_stateless_accessible: KeyDefForTest, mocked_state_repo, mocked_crypto_tool):
        self.define_key_test(empty_keys_management, DE_stateless_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_A_stated_not_accessible(self, empty_keys_management: KeysManagement,
                                     A_stated_not_accessible: KeyDefForTest, mocked_state_repo, mocked_crypto_tool):
        self.define_key_test(empty_keys_management, A_stated_not_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_A_stated_accessible(self, empty_keys_management: KeysManagement,
                                 A_stated_accessible: KeyDefForTest, mocked_state_repo, mocked_crypto_tool):
        self.define_key_test(empty_keys_management, A_stated_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_A_stateless_not_accessible(self, empty_keys_management: KeysManagement,
                                        A_stateless_not_accessible: KeyDefForTest, mocked_state_repo,
                                        mocked_crypto_tool):
        self.define_key_test(empty_keys_management, A_stateless_not_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_A_stateless_accessible(self, empty_keys_management: KeysManagement,
                                    A_stateless_accessible: KeyDefForTest, mocked_state_repo, mocked_crypto_tool):
        self.define_key_test(empty_keys_management, A_stateless_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_DE_not_cached_not_accessible(self, empty_keys_management: KeysManagement,
                                          DE_not_cached_not_accessible: KeyDefForTest, mocked_state_repo,
                                          mocked_crypto_tool):
        self.define_key_test(empty_keys_management, DE_not_cached_not_accessible, mocked_state_repo, mocked_crypto_tool)

    def test_DE_not_cached_accessible(self, empty_keys_management: KeysManagement,
                                      DE_not_cached_accessible: KeyDefForTest, mocked_state_repo, mocked_crypto_tool):
        self.define_key_test(empty_keys_management, DE_not_cached_accessible, mocked_state_repo, mocked_crypto_tool)


@mark.ofek
class TestGetKey:
    def test_key_was_not_defined__error_is_raised(self, keys_management: KeysManagement, not_defined_key_name: str,
                                                  mocked_state_repo: StateRepoInterface):
        with raises(KeyIsNotDefinedError):
            keys_management.get_key(not_defined_key_name, SecretKeyUseCase.ENCRYPTION)

        mocked_state_repo.read_state.assert_not_called()

    def test_stated_key_invalid_state(self, keys_management: KeysManagement, stated_key_def: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        def read_state(_key_name):
            if _key_name == stated_key_def.name:
                return {
                    STATE: "invalid_name",
                    KEY: stated_key_def.keys['decrypt']
                }

        mocked_state_repo.read_state.side_effect = read_state
        with raises(InvalidKeyStateError):
            keys_management.get_decrypt_key(stated_key_def.name)
        mocked_state_repo.read_state.assert_called_once_with(stated_key_def.name)

    def test_stated_key_key_from_state(self, keys_management: KeysManagement, stated_key_def: KeyDefForTest,
                                       mocked_state_repo: StateRepoInterface):
        key_from_state = 'key_from_state'

        def read_state(_key_name):
            if _key_name == stated_key_def.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_from_state
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert keys_management.get_decrypt_key(stated_key_def.name) == key_from_state
        mocked_state_repo.read_state.assert_called_once_with(stated_key_def.name)
        stated_key_def.keys_store.assert_not_called()

    def test_stated_key_when_key_not_stored(self, keys_management: KeysManagement, stated_key_def: KeyDefForTest,
                                            mocked_state_repo: StateRepoInterface):
        def read_state(_key_name):
            if _key_name == stated_key_def.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert keys_management.get_decrypt_key(stated_key_def.name) == stated_key_def.keys['decrypt']
        mocked_state_repo.read_state.assert_called_once_with(stated_key_def.name)
        stated_key_def.keys_store.assert_called_once()

    def test_stated__state_ignore_on_encrypt_purpose(self, keys_management: KeysManagement,
                                                     stated_key_def: KeyDefForTest,
                                                     mocked_state_repo: StateRepoInterface):
        assert keys_management.get_encrypt_key(stated_key_def.name) == stated_key_def.keys['encrypt']

        mocked_state_repo.read_state.assert_not_called()

        stated_key_def.keys_store.assert_called_once()


class TestGetKeyEEDDE:
    @staticmethod
    def get_key_EEDDE_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                    mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = key_definition.keys['encrypt'], key_definition.keys['decrypt']

        assert keys_management.get_encrypt_key(key_name) == expected_encrypt_key
        assert keys_management.get_encrypt_key(key_name) == expected_encrypt_key
        assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key
        assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key
        assert keys_management.get_encrypt_key(key_name) == expected_encrypt_key

        mocked_state_repo.read_state.assert_not_called()
        expected_calls_count = 3 if key_definition.is_keep_in_cache() else 4
        assert key_definition.keys_store.call_count == expected_calls_count

    def test_DE_stated_not_accessible(self, keys_management: KeysManagement,
                                      DE_stated_not_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_EEDDE_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stated_accessible(self, keys_management: KeysManagement,
                                  DE_stated_not_accessible: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        self.get_key_EEDDE_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stateless_not_accessible(self, keys_management: KeysManagement,
                                         DE_stateless_not_accessible: KeyDefForTest,
                                         mocked_state_repo: StateRepoInterface):
        self.get_key_EEDDE_scenario_test(keys_management, DE_stateless_not_accessible, mocked_state_repo)

    def test_DE_stateless_accessible(self, keys_management: KeysManagement,
                                     DE_stateless_accessible: KeyDefForTest,
                                     mocked_state_repo: StateRepoInterface):
        self.get_key_EEDDE_scenario_test(keys_management, DE_stateless_accessible, mocked_state_repo)

    def test_DE_not_cached_not_accessible_stateless(self, keys_management: KeysManagement,
                                                    DE_not_cached_not_accessible: KeyDefForTest,
                                                    mocked_state_repo: StateRepoInterface):
        self.get_key_EEDDE_scenario_test(keys_management, DE_not_cached_not_accessible, mocked_state_repo)

    def test_DE_not_cached_accessible_stateless(self, keys_management: KeysManagement,
                                                DE_not_cached_accessible: KeyDefForTest,
                                                mocked_state_repo: StateRepoInterface):
        self.get_key_EEDDE_scenario_test(keys_management, DE_not_cached_accessible, mocked_state_repo)


class TestGetKeyDDEED:
    @staticmethod
    def get_key_DDEED_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                    mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = key_definition.keys['encrypt'], key_definition.keys['decrypt']

        def read_state(_key_name):
            if _key_name == key_definition.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_definition.keys['decrypt']
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key
        assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key
        assert keys_management.get_encrypt_key(key_name) == expected_encrypt_key
        assert keys_management.get_encrypt_key(key_name) == expected_encrypt_key
        assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key

        if key_definition.is_stated():
            mocked_state_repo.read_state.assert_called_once_with(key_definition.name)
        else:
            mocked_state_repo.read_state.assert_not_called()

        expected_calls_count = 2
        # if is stateless the first get_decrypt_key require fetching from keystore
        if key_definition.is_stateless():
            expected_calls_count += 1
        if not key_definition.is_keep_in_cache():
            expected_calls_count += 1
        assert key_definition.keys_store.call_count == expected_calls_count

    def test_DE_stated_not_accessible(self, keys_management: KeysManagement,
                                      DE_stated_not_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_DDEED_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stated_accessible(self, keys_management: KeysManagement,
                                  DE_stated_not_accessible: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        self.get_key_DDEED_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stateless_not_accessible(self, keys_management: KeysManagement,
                                         DE_stateless_not_accessible: KeyDefForTest,
                                         mocked_state_repo: StateRepoInterface):
        self.get_key_DDEED_scenario_test(keys_management, DE_stateless_not_accessible, mocked_state_repo)

    def test_DE_stateless_accessible(self, keys_management: KeysManagement,
                                     DE_stateless_accessible: KeyDefForTest,
                                     mocked_state_repo: StateRepoInterface):
        self.get_key_DDEED_scenario_test(keys_management, DE_stateless_accessible, mocked_state_repo)

    def test_DE_not_cached_not_accessible(self, keys_management: KeysManagement,
                                          DE_not_cached_not_accessible: KeyDefForTest,
                                          mocked_state_repo: StateRepoInterface):
        self.get_key_DDEED_scenario_test(keys_management, DE_not_cached_not_accessible, mocked_state_repo)

    def test_DE_not_cached_accessible(self, keys_management: KeysManagement,
                                      DE_not_cached_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_DDEED_scenario_test(keys_management, DE_not_cached_accessible, mocked_state_repo)


class TestGetKeyECE:
    @staticmethod
    def get_key_ECE_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = key_definition.keys['encrypt'], key_definition.keys['decrypt']
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        assert keys_management.get_encrypt_key(key_name) == expected_encrypt_key
        key_definition.set_next_as_keys((expected_next_encrypt_key, expected_next_decrypt_key))
        assert keys_management.get_encrypt_key(key_name) == expected_next_encrypt_key

        mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(self, keys_management: KeysManagement,
                                      DE_stated_not_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_ECE_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stated_accessible(self, keys_management: KeysManagement,
                                  DE_stated_not_accessible: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        self.get_key_ECE_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stateless_not_accessible(self, keys_management: KeysManagement,
                                         DE_stateless_not_accessible: KeyDefForTest,
                                         mocked_state_repo: StateRepoInterface):
        self.get_key_ECE_scenario_test(keys_management, DE_stateless_not_accessible, mocked_state_repo)

    def test_DE_stateless_accessible(self, keys_management: KeysManagement,
                                     DE_stateless_accessible: KeyDefForTest,
                                     mocked_state_repo: StateRepoInterface):
        self.get_key_ECE_scenario_test(keys_management, DE_stateless_accessible, mocked_state_repo)

    def test_DE_not_cached_not_accessible(self, keys_management: KeysManagement,
                                          DE_not_cached_not_accessible: KeyDefForTest,
                                          mocked_state_repo: StateRepoInterface):
        self.get_key_ECE_scenario_test(keys_management, DE_not_cached_not_accessible, mocked_state_repo)

    def test_DE_not_cached_accessible(self, keys_management: KeysManagement,
                                      DE_not_cached_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_ECE_scenario_test(keys_management, DE_not_cached_accessible, mocked_state_repo)


class TestGetKeyECD:
    @staticmethod
    def get_key_ECD_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = key_definition.keys['encrypt'], key_definition.keys['decrypt']
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        assert keys_management.get_encrypt_key(key_name) == expected_encrypt_key
        key_definition.set_next_as_keys((expected_next_encrypt_key, expected_next_decrypt_key))
        after_key_changed_key = keys_management.get_decrypt_key(key_name)

        assert after_key_changed_key == expected_decrypt_key

        mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(self, keys_management: KeysManagement,
                                      DE_stated_not_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_ECD_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stated_accessible(self, keys_management: KeysManagement,
                                  DE_stated_not_accessible: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        self.get_key_ECD_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stateless_not_accessible(self, keys_management: KeysManagement,
                                         DE_stateless_not_accessible: KeyDefForTest,
                                         mocked_state_repo: StateRepoInterface):
        self.get_key_ECD_scenario_test(keys_management, DE_stateless_not_accessible, mocked_state_repo)

    def test_DE_stateless_accessible(self, keys_management: KeysManagement,
                                     DE_stateless_accessible: KeyDefForTest,
                                     mocked_state_repo: StateRepoInterface):
        self.get_key_ECD_scenario_test(keys_management, DE_stateless_accessible, mocked_state_repo)

    def test_DE_not_cached_not_accessible(self, keys_management: KeysManagement,
                                          DE_not_cached_not_accessible: KeyDefForTest,
                                          mocked_state_repo: StateRepoInterface):
        self.get_key_ECD_scenario_test(keys_management, DE_not_cached_not_accessible, mocked_state_repo)

    def test_DE_not_cached_accessible(self, keys_management: KeysManagement,
                                      DE_not_cached_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_ECD_scenario_test(keys_management, DE_not_cached_accessible, mocked_state_repo)


class TestGetKeyDCE:
    @staticmethod
    def get_key_DCE_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = key_definition.keys['encrypt'], key_definition.keys['decrypt']
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        def read_state(_key_name):
            if _key_name == key_definition.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_definition.keys['decrypt']
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key
        key_definition.set_next_as_keys((expected_next_encrypt_key, expected_next_decrypt_key))
        assert keys_management.get_encrypt_key(key_name) == expected_next_encrypt_key

        if key_definition.is_stated():
            mocked_state_repo.read_state.assert_called_once_with(key_definition.name)
        else:
            mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(self, keys_management: KeysManagement,
                                      DE_stated_not_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_DCE_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stated_accessible(self, keys_management: KeysManagement,
                                  DE_stated_not_accessible: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        self.get_key_DCE_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stateless_not_accessible(self, keys_management: KeysManagement,
                                         DE_stateless_not_accessible: KeyDefForTest,
                                         mocked_state_repo: StateRepoInterface):
        self.get_key_DCE_scenario_test(keys_management, DE_stateless_not_accessible, mocked_state_repo)

    def test_DE_stateless_accessible(self, keys_management: KeysManagement,
                                     DE_stateless_accessible: KeyDefForTest,
                                     mocked_state_repo: StateRepoInterface):
        self.get_key_DCE_scenario_test(keys_management, DE_stateless_accessible, mocked_state_repo)

    def test_DE_not_cached_not_accessible(self, keys_management: KeysManagement,
                                          DE_not_cached_not_accessible: KeyDefForTest,
                                          mocked_state_repo: StateRepoInterface):
        self.get_key_DCE_scenario_test(keys_management, DE_not_cached_not_accessible, mocked_state_repo)

    def test_DE_not_cached_accessible(self, keys_management: KeysManagement,
                                      DE_not_cached_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_DCE_scenario_test(keys_management, DE_not_cached_accessible, mocked_state_repo)


class TestGetKeyDCD:
    @staticmethod
    def get_key_DCD_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_encrypt_key, expected_decrypt_key = key_definition.keys['encrypt'], key_definition.keys['decrypt']
        expected_next_encrypt_key = "new_" + expected_encrypt_key
        expected_next_decrypt_key = "new_" + expected_decrypt_key

        def read_state(_key_name):
            if _key_name == key_definition.name:
                return {
                    STATE: SecretKeyUseCase.DECRYPTION.name,
                    KEY: key_definition.keys['decrypt']
                }

        mocked_state_repo.read_state.side_effect = read_state

        assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key
        key_definition.set_next_as_keys((expected_next_encrypt_key, expected_next_decrypt_key))
        if key_definition.is_keep_in_cache():
            assert keys_management.get_decrypt_key(key_name) == expected_decrypt_key
        else:
            assert keys_management.get_decrypt_key(key_name) == expected_next_decrypt_key

        if key_definition.is_stated():
            mocked_state_repo.read_state.assert_called_once_with(key_definition.name)
        else:
            mocked_state_repo.read_state.assert_not_called()

    def test_DE_stated_not_accessible(self, keys_management: KeysManagement,
                                      DE_stated_not_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_DCD_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stated_accessible(self, keys_management: KeysManagement,
                                  DE_stated_not_accessible: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        self.get_key_DCD_scenario_test(keys_management, DE_stated_not_accessible, mocked_state_repo)

    def test_DE_stateless_not_accessible(self, keys_management: KeysManagement,
                                         DE_stateless_not_accessible: KeyDefForTest,
                                         mocked_state_repo: StateRepoInterface):
        self.get_key_DCD_scenario_test(keys_management, DE_stateless_not_accessible, mocked_state_repo)

    def test_DE_stateless_accessible(self, keys_management: KeysManagement,
                                     DE_stateless_accessible: KeyDefForTest,
                                     mocked_state_repo: StateRepoInterface):
        self.get_key_DCD_scenario_test(keys_management, DE_stateless_accessible, mocked_state_repo)

    def test_DE_not_cached_not_accessible(self, keys_management: KeysManagement,
                                          DE_not_cached_not_accessible: KeyDefForTest,
                                          mocked_state_repo: StateRepoInterface):
        self.get_key_DCD_scenario_test(keys_management, DE_not_cached_not_accessible, mocked_state_repo)

    def test_DE_not_cached_accessible(self, keys_management: KeysManagement,
                                      DE_not_cached_accessible: KeyDefForTest,
                                      mocked_state_repo: StateRepoInterface):
        self.get_key_DCD_scenario_test(keys_management, DE_not_cached_accessible, mocked_state_repo)


class TestGetKeyA:
    @staticmethod
    def get_key_AA_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                 mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_key = key_definition.keys

        assert keys_management.get_key(key_name, SecretKeyUseCase.AUTHENTICATION) == expected_key
        assert keys_management.get_key(key_name, SecretKeyUseCase.AUTHENTICATION) == expected_key
        mocked_state_repo.read_state.assert_not_called()

    @staticmethod
    def get_key_ACA_scenario_test(keys_management: KeysManagement, key_definition: KeyDefForTest,
                                  mocked_state_repo: StateRepoInterface):
        key_name = key_definition.name
        expected_key = key_definition.keys
        expected_next_key = "new_" + expected_key

        assert keys_management.get_key(key_name, SecretKeyUseCase.AUTHENTICATION) == expected_key
        key_definition.set_next_as_keys(expected_next_key)
        assert keys_management.get_key(key_name, SecretKeyUseCase.AUTHENTICATION) == expected_next_key
        mocked_state_repo.read_state.assert_not_called()

    def test_get_key_AA_scenario_A_stated_not_accessible(self, keys_management: KeysManagement,
                                                         A_stated_not_accessible: KeyDefForTest,
                                                         mocked_state_repo: StateRepoInterface):
        self.get_key_AA_scenario_test(keys_management, A_stated_not_accessible, mocked_state_repo)

    def test_get_key_AA_scenario_A_stated_accessible(self, keys_management: KeysManagement,
                                                     A_stated_accessible: KeyDefForTest,
                                                     mocked_state_repo: StateRepoInterface):
        self.get_key_AA_scenario_test(keys_management, A_stated_accessible, mocked_state_repo)

    def test_get_key_AA_scenario_A_stateless_not_accessible(self, keys_management: KeysManagement,
                                                            A_stateless_not_accessible: KeyDefForTest,
                                                            mocked_state_repo: StateRepoInterface):
        self.get_key_AA_scenario_test(keys_management, A_stateless_not_accessible, mocked_state_repo)

    def test_get_key_AA_scenario_A_stateless_accessible(self, keys_management: KeysManagement,
                                                        A_stateless_accessible: KeyDefForTest,
                                                        mocked_state_repo: StateRepoInterface):
        self.get_key_AA_scenario_test(keys_management, A_stateless_accessible, mocked_state_repo)

    def test_get_key_ACA_scenario_A_stated_not_accessible(self, keys_management: KeysManagement,
                                                          A_stated_not_accessible: KeyDefForTest,
                                                          mocked_state_repo: StateRepoInterface):
        self.get_key_ACA_scenario_test(keys_management, A_stated_not_accessible, mocked_state_repo)

    def test_get_key_ACA_scenario_A_stated_accessible(self, keys_management: KeysManagement,
                                                      A_stated_accessible: KeyDefForTest,
                                                      mocked_state_repo: StateRepoInterface):
        self.get_key_ACA_scenario_test(keys_management, A_stated_accessible, mocked_state_repo)

    def test_get_key_ACA_scenario_A_stateless_not_accessible(self, keys_management: KeysManagement,
                                                             A_stateless_not_accessible: KeyDefForTest,
                                                             mocked_state_repo: StateRepoInterface):
        self.get_key_ACA_scenario_test(keys_management, A_stateless_not_accessible, mocked_state_repo)

    def test_get_key_ACA_scenario_A_stateless_accessible(self, keys_management: KeysManagement,
                                                         A_stateless_accessible: KeyDefForTest,
                                                         mocked_state_repo: StateRepoInterface):
        self.get_key_ACA_scenario_test(keys_management, A_stateless_accessible, mocked_state_repo)


@fixture
def empty_keys_management(mocked_state_repo: StateRepoInterface, mocked_crypto_tool: CryptoTool) -> KeysManagement:
    mocked_crypto_tool.decrypt.side_effect = lambda data: data
    mocked_crypto_tool.encrypt.side_effect = lambda data: data
    return KeysManagementImpl(mocked_state_repo, mocked_crypto_tool)
