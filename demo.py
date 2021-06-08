# mypy: ignore
from unittest.mock import Mock
from keys_management import KeysManagementImpl, OnChangeKeyDefinition, SecretKeyUseCase

print_mock = Mock()

KEY_NAME = "my_first_key"
FIRST_VALUE = "value_1"
SECOND_VALUE = "value_2"
current_value = FIRST_VALUE


def key_store():
    return current_value


def on_change(
    old_key: str, new_key: str, on_change_key_definition: OnChangeKeyDefinition
):
    print_mock("key_changed from {} to {}.".format(old_key, new_key))


key_definition_properties = {
    "stateless": True,
    "use_case": SecretKeyUseCase.AUTHENTICATION,
    "target_data_accessible": True,
    "keep_in_cache": True,
}

keys_management = KeysManagementImpl(state_repo=Mock(), crypto_tool=Mock())
keys_management.define_key(KEY_NAME, key_store, **key_definition_properties)
keys_management.register_on_change(KEY_NAME, on_change)

assert keys_management.get_key(KEY_NAME) == FIRST_VALUE
current_value = SECOND_VALUE
keys_management.key_changed(KEY_NAME, FIRST_VALUE, SECOND_VALUE)
print_mock.assert_called_once_with(
    "key_changed from {} to {}.".format(FIRST_VALUE, SECOND_VALUE)
)
assert keys_management.get_key(KEY_NAME) == SECOND_VALUE
