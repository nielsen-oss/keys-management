# mypy: ignore
from unittest.mock import Mock
from keys_management import (
    KeysManagementImpl,
    OnChangeKeyDefinition,
    SecretKeyFlow,
    SecretKeyUseCase,
)

KEY_NAME = "my_first_key"
FIRST_VALUE = "value_1"
SECOND_VALUE = "value_2"
current_value = FIRST_VALUE


def key_store():
    return current_value


print_mock = Mock()


def on_change(
    old_key: str, new_key: str, on_change_key_definition: OnChangeKeyDefinition
):
    print_mock("key_changed from {} to {}.".format(old_key, new_key))


key_definition_properties = {
    "stateless": True,
    "use_case": SecretKeyUseCase.ROUND_TRIP,
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


# example 1

# 3rd_party_client package
class ClientExample:
    def __init__(self, access_token):
        self.set_access_token(access_token)

    def get_data(self):
        """use the access token and return some data"""
        pass

    def set_access_token(self, access_token):
        self.access_token = access_token


from os import environ

CLIENT_ACCESS_TOKEN = "CLIENT_ACCESS_TOKEN"


def key_from_env():
    return environ.get(CLIENT_ACCESS_TOKEN)


# no need to define it with: stateless, target_data_accessible and keep_in_cache
# since it used with AUTHENTICATION use_case, no state is required
keys_management.define_key(
    CLIENT_ACCESS_TOKEN, key_from_env, use_case=SecretKeyUseCase.ONE_WAY_TRIP
)


client = ClientExample(access_token=keys_management.get_key(CLIENT_ACCESS_TOKEN))

# client object "state" the access token so key_changed should be declare to set new
# access token for using the client.
def on_client_access_token_changed(
    old_key: str, new_key: str, on_change_key_definition: OnChangeKeyDefinition
):
    client.set_access_token(new_key)


keys_management.register_on_change(CLIENT_ACCESS_TOKEN, on_client_access_token_changed)

first_data = client.get_data()

environ[CLIENT_ACCESS_TOKEN] = "new_token"

first_data = client.get_data()  # raise an error since client use old token

keys_management.key_changed(CLIENT_ACCESS_TOKEN, new_keys="new_token")

second_data = client.get_data()


# example 2 - sensitive data inside the server
# assume there is a sensitive information contains called example2_data
# the data is stored in a file - it can be encrypted or plain
# the data is very important and should not be lost, thus the decrypt key should not be
# lost, so it should be stated and kept in cache.
# the data can reached anytime so is accessible

EXAMPLE2_KEY_NAME = "EXAMPLE2_DATA"
EXAMPLE2_DATA_ENCRYPT_KEY = "EXAMPLE2_DATA_ENCRYPT_KEY"
EXAMPLE2_DATA_DECRYPT_KEY = "EXAMPLE2_DATA_DECRYPT_KEY"

import importlib

def example2_key_store_asymetric_keys():
    # assume there is an app.config module
    import app.config as config_module

    # it should be reloaded to get the most updated values
    importlib.reload(config_module)
    return config_module.get(EXAMPLE2_DATA_ENCRYPT_KEY), config_module.get(
        EXAMPLE2_DATA_DECRYPT_KEY
    )


keys_management.define_key(
    EXAMPLE2_KEY_NAME,
    example2_key_store_asymetric_keys,
    stateless=False,
    keep_in_cache=True,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)


# key changed example one - decrypt, then encrypt again
def on_example2_data_key_changed(
    old_keys, new_keys, on_change_key_definition: OnChangeKeyDefinition
):
    if on_change_key_definition.get_last_flow() is SecretKeyFlow.FORWARD_PATH:
        example2_data = get_example2_data(key=old_keys[1])  # decrypt with the old key
        save_example2_data(example2_data, key=new_keys[0])  # encrypt with new key
    keys_management.save_state(on_change_key_definition.name)


# key changed example two: only decrypt
def on_example2_data_key_changed2(
    old_keys, new_keys, on_change_key_definition: OnChangeKeyDefinition
):
    if on_change_key_definition.get_last_flow() is SecretKeyFlow.FORWARD_PATH:
        people_data = get_example2_data(key=old_keys[1])  # decrypt with the old key
        # since it only decrypt the data, change the data
        on_change_key_definition.set_last_flow(SecretKeyFlow.BACK_PATH)
    # here we don't save the state, our app calls save states on exit/or failures


## application lifetime 1:
save_example2_data(
    example2_data, key=keys_management.get_forward_path_key(EXAMPLE2_KEY_NAME)
)

## application lifetime 2:
## first time use on that lifetime - key is fetched from state repository
example2_data = get_example2_data(keys_management.get_back_path_key(EXAMPLE2_KEY_NAME))

## for some reason, the decrypt key should be get again - fetched from cache
decrypt_key = keys_management.get_back_path_key(EXAMPLE2_KEY_NAME)


## after a while:
save_example2_data(
    example2_data, key=keys_management.get_forward_path_key(EXAMPLE2_KEY_NAME)
)


keys_management.register_on_change(EXAMPLE2_KEY_NAME, on_example2_data_key_changed)
## or
keys_management.register_on_change(EXAMPLE2_KEY_NAME, on_example2_data_key_changed2)


## once the application admin decides to the change key, declare the change
keys_management.key_changed(
    EXAMPLE2_KEY_NAME,
    example2_key_store_asymetric_keys(),
    ("new_encrypt_key", "new_decrypt_key"),
)

## assume the key changed:
example2_data = get_example2_data(keys_management.get_back_path_key(EXAMPLE2_KEY_NAME))


# example 3 - sensitive data inside the server, but not so important, but still would
# like maintains in cache

EXAMPLE3_DATA = "EXAMPLE3_DATA"
EXAMPLE3_DATA_KEY = "EXAMPLE3_DATA_KEY"

import importlib


def example3_key_from_config_module():
    # assume there is an app.config module
    import app.config as config_module

    # it should be reloaded to get the most updated values
    importlib.reload(config_module)
    return config_module.get(EXAMPLE3_DATA_KEY)


# the data is very important and should not be lost, thus the decrypt key should not be
# lost, so it should be stated and kept in cache.
# the data can reached anytime so is accessible
keys_management.define_key(
    EXAMPLE3_DATA,
    example3_key_from_config_module,
    stateless=True,
    keep_in_cache=True,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)

## lets assume there is a file contains the data - it can be encrypted data or plain

## application lifetime 1:
save_example3_data(
    example3_data, key=keys_management.get_forward_path_key(EXAMPLE3_DATA)
)

## application lifetime 2:
## first key use on that lifetime - key is fetched from store, assume the returned key
# is the same as lifetime 1
example3_data = get_example3_data(keys_management.get_back_path_key(EXAMPLE3_DATA))
## after a while:
save_example3_data(
    example3_data, key=keys_management.get_forward_path_key(EXAMPLE3_DATA)
)
## after another time, no matter where and why the key was changed
## note - callback was not defined,

## we get the old key - data was not lost
example3_data = get_example3_data(keys_management.get_back_path_key(EXAMPLE3_DATA))

## we get the new key
keys_management.get_back_path_key(EXAMPLE3_DATA)


# example4 - sensitive data inside the server, without cache, without state ,
# AWS key store

EXAMPLE4_DATA = "EXAMPLE4_DATA"
EXAMPLE4_DATA_KEY = "EXAMPLE4_DATA_KEY"

import importlib


def example4_key_from_aws():
    import boto3

    sqs = boto3.resource("keys_resource")
    # other code fetching the key
    return key_from_aws


# the data is very important and should not be lost, thus the decrypt key should not be
# lost, so it should be stated and kept in cache.
# the data can reached anytime so is accessible
keys_management.define_key(
    EXAMPLE4_DATA,
    example4_key_from_aws,
    stateless=False,
    keep_in_cache=False,
    target_data_accessible=True,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)

## lets assume there is a file contains the data - it can be encrypted data or plain
## key fetched from store
save_example4_data(
    example4_data, key=keys_management.get_forward_path_key(EXAMPLE4_DATA)
)

## key fetched from store - there is no cache
example4_data = get_example4_data(keys_management.get_back_path_key(EXAMPLE4_DATA))

## after a while:
save_example4_data(
    example4_data, key=keys_management.get_forward_path_key(EXAMPLE4_DATA)
)
## after another time, no matter where and why the key was changed
## note - callback was not defined,

## there is no use of cache - we get the new key - old decrpyt key was lost
example4_data = get_example4_data(keys_management.get_back_path_key(EXAMPLE4_DATA))


# example 5 - third party library encrypt and decrypt the data

# the app use the library but cannot really trace the use of the key.
## the library treats the key as symmetric but the app would like to use asymmetric
class ThirdPartyLibrary:
    def __init__(self, get_key_method):
        self.get_key_method = get_key_method

    def get_data(self):
        """use the get_key_method"""
        pass

    def create_data(
        self,
    ):
        """use the get_key_method for saving the created data"""

    def __internal_method(self):
        """use the get_key_method"""


FAKE_LIBRARY_KEY_NAME = "FAKE_LIBRARY_KEY"
FAKE_LIBRARY_ENCRYPT_KEY = "FAKE_LIBRARY_ENCRYPT_KEY"
FAKE_LIBRARY_DECRYPT_KEY = "FAKE_LIBRARY_DECRYPT_KEY"


def key_store_from_env():
    return environ.get(FAKE_LIBRARY_ENCRYPT_KEY), environ.get(FAKE_LIBRARY_DECRYPT_KEY)


# the data is very important and should not be lost, thus the decrypt key should not be
# lost, so it should be stated and kept in cache.
# the data can reached anytime so is accessible
keys_management.define_key(
    FAKE_LIBRARY_KEY_NAME,
    key_store_from_env,
    stateless=False,
    keep_in_cache=True,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)

library = ThirdPartyLibrary(lambda: keys_management.get_key(FAKE_LIBRARY_KEY_NAME))

## application lifetime 1:
## keys-management determine the use-case and will return the encryption key first
library.create_data()

## keys-management determine the use-case and will return decryption key based on the
# state
## application lifetime 2:
library.get_data()

## keys-management determine the use-case and will return encryption key based on
# previous usage
library.create_data()
