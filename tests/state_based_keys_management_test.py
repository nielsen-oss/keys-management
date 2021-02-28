from typing import Tuple
from pytest import raises, fixture
from pytest_mock import MockerFixture
from keys_management import CryptoTool, StateRepoInterface, KeysStore, KeysManagement
from keys_management.state_based_keys_management import KeysManagementStateBased, UnknownState, KeyIsNotDefinedError, StateFactory
from keys_management.consts import *
from keys_management.key_state import UndefinedOperationError, KeyState
from keys_management.key_state.decrypted_state import DecryptedState
from keys_management.key_state.encrypted_state import EncryptedState
from . import KeyDef


class TestKeysManagementStateBased:
    def test_define_key(self, empty_keys_management: KeysManagement, key_def: KeyDef, patched_unknown_state, mocked_state_repo, mocked_crypto_tool):
        key_name = key_def.name
        keys_store = key_def.keys_store
        # act
        empty_keys_management.define_key(key_name, keys_store)
        # assert
        defined_key = empty_keys_management.keys[key_name]
        assert defined_key is not None
        assert defined_key[KEEP_STATE] is not None
        patched_unknown_state.assert_called_once()
        assert defined_key[STATE] is not None and defined_key[STATE] is patched_unknown_state()
        assert defined_key[KEYS_STORE] == keys_store
        assert defined_key[ON_CHANGES_CALLBACKS] is not None and len(defined_key[ON_CHANGES_CALLBACKS]) == 0
        keys_store.assert_not_called()
        assert len(mocked_state_repo.method_calls) == 0
        assert len(mocked_crypto_tool.method_calls) == 0

    def test_get_key__key_was_not_defined__error_is_raised(self, keys_management: KeysManagement, not_defined_key_name: str):
        with raises(KeyIsNotDefinedError):
            keys_management.get_key(not_defined_key_name)

    def test_get_key__stateless_key__unknown_state(self, keys_management: KeysManagement, stateless_key_def: KeyDef, patched_state_factory, mocked_states, mocked_state_repo: StateRepoInterface):
        '''
        (unknown) => (decrypted) => (encrypted) => (decrypted)
        '''
        mock_decrypted_state, mock_encrypted_state = mocked_states

        #act 1
        rv_key = keys_management.get_key(stateless_key_def.name)
        # assert
        assert rv_key == stateless_key_def.keys['encrypt']
        patched_state_factory.create_state.assert_called_once_with('decrypted', stateless_key_def.keys_store)
        mock_decrypted_state.enter.assert_called_once()
        mock_decrypted_state.exit.assert_called_once()
        mock_encrypted_state.enter.assert_called_once()
        assert keys_management.keys[stateless_key_def.name][STATE].get_name() is 'EncryptedState'
        mock_encrypted_state.exit.assert_not_called()
        mocked_state_repo.read_state.assert_not_called()
        mocked_state_repo.write_state.assert_not_called()

        #arrange
        patched_state_factory.reset_mock()
        mock_decrypted_state.reset_mock()
        mock_encrypted_state.reset_mock()

        #act 2
        rv_key = keys_management.get_key(stateless_key_def.name)

        # assert 2
        assert rv_key == stateless_key_def.keys['decrypt']
        patched_state_factory.create_state.assert_not_called()
        mock_encrypted_state.exit.assert_called_once()
        mock_decrypted_state.enter.assert_called_once()
        assert keys_management.keys[stateless_key_def.name][STATE].get_name() is 'DecryptedState'
        mocked_state_repo.read_state.assert_not_called()
        mocked_state_repo.write_state.assert_not_called()

    def test_get_key__stated_key__unknown_state__invalid_state(self, keys_management: KeysManagement, stated_key_def: KeyDef, patched_state_factory, mocked_states, mocked_state_repo: StateRepoInterface, mocked_crypto_tool: CryptoTool):
        mock_decrypted_state, mock_encrypted_state = mocked_states
        mocked_crypto_tool.decrypt.side_effect = lambda data: data
        invalid_state = 'invalid'
        def read_state(key_name):
            if key_name == stated_key_def.name:
                return {
                    STATE: invalid_state,
                    KEY: stated_key_def.keys['decrypt']
                }

        mocked_state_repo.read_state.side_effect = read_state


        with raises(UndefinedOperationError):
            keys_management.get_key(stated_key_def.name)


        # assert
        mocked_state_repo.read_state.assert_called_once_with(stated_key_def.name)
        patched_state_factory.create_state.assert_called_once_with(invalid_state, stated_key_def.keys_store, stated_key_def.keys['decrypt'])
        assert keys_management.keys[stated_key_def.name][STATE].get_name() is 'UnknownState'
        mock_decrypted_state.enter.assert_not_called()
        mock_decrypted_state.exit.assert_not_called()
        mock_encrypted_state.enter.assert_not_called()
        mock_encrypted_state.exit.assert_not_called()

    def test_get_key__stated_key__unknown_state_to_encrypted__without_key(self, keys_management: KeysManagement, stated_key_def: KeyDef, patched_state_factory, mocked_states, mocked_state_repo: StateRepoInterface, mocked_crypto_tool: CryptoTool):
        mock_decrypted_state, mock_encrypted_state = mocked_states
        mocked_crypto_tool.decrypt.side_effect = lambda data: data
        invalid_state = 'invalid'
        def read_state(key_name):
            if key_name == stated_key_def.name:
                return {
                    STATE: invalid_state,
                }

        mocked_state_repo.read_state.side_effect = read_state


        with raises(UndefinedOperationError):
            keys_management.get_key(stated_key_def.name)


        # assert
        mocked_state_repo.read_state.assert_called_once_with(stated_key_def.name)
        patched_state_factory.create_state.assert_called_once_with(invalid_state, stated_key_def.keys_store, None)
        assert keys_management.keys[stated_key_def.name][STATE].get_name() is 'UnknownState'
        mock_decrypted_state.enter.assert_not_called()
        mock_decrypted_state.exit.assert_not_called()
        mock_encrypted_state.enter.assert_not_called()
        mock_encrypted_state.exit.assert_not_called()

    def test_get_key__stated_key__unknown_state_to_decrypted(self, keys_management: KeysManagement, stated_key_def: KeyDef, patched_state_factory, mocked_states, mocked_state_repo: StateRepoInterface, mocked_crypto_tool: CryptoTool):
        mock_decrypted_state, mock_encrypted_state = mocked_states
        mocked_crypto_tool.decrypt.side_effect = lambda data: data

        def read_state(key_name):
            if key_name == stated_key_def.name:
                return {
                    STATE: 'decrypted'
                }

        mocked_state_repo.read_state.side_effect = read_state

        #act 1
        rv_key = keys_management.get_key(stated_key_def.name)

        # assert
        assert rv_key == stated_key_def.keys['encrypt']
        patched_state_factory.create_state.assert_called_once_with('decrypted', stated_key_def.keys_store, None)
        mocked_state_repo.read_state.assert_called_once_with(stated_key_def.name)
        mock_decrypted_state.enter.assert_called_once()
        mock_decrypted_state.exit.assert_called_once()
        mock_encrypted_state.enter.assert_called_once()
        assert keys_management.keys[stated_key_def.name][STATE].get_name() is 'EncryptedState'
        mock_encrypted_state.exit.assert_not_called()
        mocked_state_repo.write_state.assert_not_called()

        #arrange
        mocked_state_repo.reset_mock()
        patched_state_factory.reset_mock()
        mock_decrypted_state.reset_mock()
        mock_encrypted_state.reset_mock()

        #act 2
        rv_key = keys_management.get_key(stated_key_def.name)

        # assert 2
        assert rv_key == stated_key_def.keys['decrypt']
        patched_state_factory.create_state.assert_not_called()
        mock_encrypted_state.exit.assert_called_once()
        mock_decrypted_state.enter.assert_called_once()
        assert keys_management.keys[stated_key_def.name][STATE].get_name() is 'DecryptedState'
        mocked_state_repo.read_state.assert_not_called()
        mocked_state_repo.write_state.assert_not_called()

    def test_get_key__stated_key__unknown_state_to_encrypted(self, keys_management: KeysManagement, stated_key_def: KeyDef, patched_state_factory, mocked_states, mocked_state_repo: StateRepoInterface, mocked_crypto_tool: CryptoTool):
        mock_decrypted_state, mock_encrypted_state = mocked_states
        mocked_crypto_tool.decrypt.side_effect = lambda data: data
        state_name = 'encrypted'
        def read_state(key_name):
            if key_name == stated_key_def.name:
                return {
                    STATE: state_name,
                    KEY: stated_key_def.keys['encrypt']
                }

        mocked_state_repo.read_state.side_effect = read_state

        #act 1
        rv_key = keys_management.get_key(stated_key_def.name)

        # assert
        assert rv_key == stated_key_def.keys['decrypt']
        patched_state_factory.create_state.assert_called_once_with(state_name, stated_key_def.keys_store, rv_key)
        mocked_state_repo.read_state.assert_called_once_with(stated_key_def.name)
        mock_encrypted_state.enter.assert_called_once()
        mock_encrypted_state.exit.assert_called_once()
        assert keys_management.keys[stated_key_def.name][STATE].get_name() is 'DecryptedState'
        mock_decrypted_state.enter.assert_called_once()
        mocked_state_repo.write_state.assert_not_called()

        #arrange
        mocked_state_repo.reset_mock()
        patched_state_factory.reset_mock()
        mock_decrypted_state.reset_mock()
        mock_encrypted_state.reset_mock()

        #act 2
        rv_key = keys_management.get_key(stated_key_def.name)

        # assert 2
        assert rv_key == stated_key_def.keys['encrypt']
        patched_state_factory.create_state.assert_not_called()
        mock_decrypted_state.exit.assert_called_once()
        mock_encrypted_state.enter.assert_called_once()
        assert keys_management.keys[stated_key_def.name][STATE].get_name() is 'EncryptedState'
        mocked_state_repo.read_state.assert_not_called()
        mocked_state_repo.write_state.assert_not_called()

    def test_get_key__when_key_changed_from_store(self, keys_management: KeysManagement, stateless_key_def: KeyDef, patched_state_factory, mocked_states, mocked_state_repo: StateRepoInterface):
        '''
        (unknown) => (decrypted) => (encrypted) => (decrypted)
        '''
        mock_decrypted_state, mock_encrypted_state = mocked_states

        #arrange
        keys_management.get_key(stateless_key_def.name)
        assert keys_management.keys[stateless_key_def.name][STATE].get_name() is 'EncryptedState'
        patched_state_factory.reset_mock()
        mock_decrypted_state.reset_mock()
        mock_encrypted_state.reset_mock()
        previous_encrypt_key = stateless_key_def.keys['encrypt']
        previous_decrypt_key = stateless_key_def.keys['decrypt']
        stateless_key_def.set_next_as_keys({
            "encrypt": "next_encrypt_key",
            "decrypt": "next_decrypt_key"
        })

        #act 1
        rv_key = keys_management.get_key(stateless_key_def.name)

        # assert 1
        assert rv_key == previous_decrypt_key
        patched_state_factory.create_state.assert_not_called()
        mock_encrypted_state.exit.assert_called_once()
        mock_decrypted_state.enter.assert_called_once()
        assert keys_management.keys[stateless_key_def.name][STATE].get_name() is 'DecryptedState'
        mocked_state_repo.read_state.assert_not_called()
        mocked_state_repo.write_state.assert_not_called()

        #act 2
        current_encrypt_key = stateless_key_def.keys['encrypt']
        assert current_encrypt_key != previous_encrypt_key

        rv_key = keys_management.get_key(stateless_key_def.name)
        assert rv_key == current_encrypt_key

        #act 3
        current_decrypt_key = stateless_key_def.keys['decrypt']
        assert current_decrypt_key != previous_encrypt_key

        rv_key = keys_management.get_key(stateless_key_def.name)
        assert rv_key == current_decrypt_key

    def test_on_change_invalid_key(self, keys_management: KeysManagement, not_defined_key_name: str):
        with raises(KeyIsNotDefinedError):
            keys_management.on_change(not_defined_key_name, lambda n, o: n)

    def test_on_change__with_key_changed(self, keys_management: KeysManagement, stated_key_def: KeyDef, mocker: MockerFixture):
        first_on_change_mock = mocker.MagicMock()
        second_on_change_mock = mocker.MagicMock()

        keys_management.on_change(stated_key_def.name, first_on_change_mock)
        keys_management.on_change(stated_key_def.name, second_on_change_mock)

        old_key = "old_key"
        new_key = "new_key"

        keys_management.key_changed(stated_key_def.name, old_key, new_key)

        first_on_change_mock.assert_called_once_with(old_key, new_key)
        second_on_change_mock.assert_called_once_with(old_key, new_key)


@fixture
def mocked_state_repo(mocker: MockerFixture) -> StateRepoInterface:
    return mocker.patch('keys_management.StateRepoInterface', spec_set=True)


@fixture
def mocked_crypto_tool(mocker: MockerFixture) -> CryptoTool:
    return mocker.patch('keys_management.CryptoTool', create=True, spec_set=True)


@fixture
def empty_keys_management(mocked_state_repo: StateRepoInterface, mocked_crypto_tool: CryptoTool) -> KeysManagement:
    return KeysManagementStateBased(mocked_state_repo, mocked_crypto_tool)


@fixture(autouse=True)
def patched_unknown_state(mocker: MockerFixture) -> UnknownState.__class__:
    mocked_object = mocker.NonCallableMock(wraps=UnknownState(), name='UnknownState')
    return mocker.patch('keys_management.state_based_keys_management.UnknownState', return_value=mocked_object)


@fixture
def mocked_encrypted_state(mocker: MockerFixture):
    real_obj = EncryptedState()
    mocked_object = mocker.MagicMock(spec=real_obj, wraps=real_obj)
    type(mocked_object).name = mocker.PropertyMock(return_value='EncryptedState')
    class side:
        def __init__(self):
            self.prop = None
        def __call__(self, arg=None):
            if arg:
                self.prop = arg
            return self.prop


    type(mocked_object).opposite_state = mocker.PropertyMock(side_effect=side())


    return mocked_object


@fixture
def mocked_states(mocker: MockerFixture) -> Tuple[KeyState, KeyState]:
    real_decrypted_state = DecryptedState()
    real_encrypted_state = EncryptedState()
    mocked_decrypted_state = mocker.MagicMock(spec=real_decrypted_state, wraps=real_decrypted_state, name='DecryptedState')
    mocked_encrypted_state = mocker.MagicMock(spec=real_encrypted_state, wraps=real_encrypted_state, name='EncryptedState')
    real_decrypted_state.set_opposite_state(mocked_encrypted_state)
    real_encrypted_state.set_opposite_state(mocked_decrypted_state)
    return mocked_decrypted_state, mocked_encrypted_state


@fixture(autouse=True)
def patched_state_factory(mocker: MockerFixture, mocked_states):
    mocked_decrypted_state, mocked_encrypted_state = mocked_states
    def side_effect(state_name, keys_store = None, key = None):
        state_name = state_name.lower()
        if state_name in {ENCRYPTED_STATE, DECRYPTED_STATE}:
            rv_state = mocked_decrypted_state if state_name == DECRYPTED_STATE else mocked_encrypted_state
            rv_state.set_keys_store(keys_store)
            rv_state.set_key(key)
            return rv_state
        else:
            raise UndefinedOperationError('create_state', 'the state name "%s" is not defined' % state_name)

    config = {'create_state.side_effect': side_effect}
    return mocker.patch('keys_management.state_based_keys_management.StateFactory', new_callable=mocker.NonCallableMock, spec=True, **config)


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
def stateless_key_def(stateless_key_name: str, stateless_key: str) -> KeyDef:
    return KeyDef(stateless_key_name, stateless_key)


@fixture
def stated_key_def(stated_key_name, stated_key) -> KeyDef:
    return KeyDef(stated_key_name, stated_key)


@fixture
def keys_management(empty_keys_management: KeysManagement, stateless_key_def: KeyDef, stated_key_def: KeyDef):
    return empty_keys_management.define_key(stateless_key_def.name, stateless_key_def.keys_store, False).define_key(stated_key_def.name, stated_key_def.keys_store, True)


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
def key_def(key_name: str, stated_key: str):
    return KeyDef(key_name, stated_key, keys_store)
