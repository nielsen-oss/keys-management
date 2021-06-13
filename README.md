# keys-management
pip package: https://pypi.org/project/keys-management/

[![image](https://img.shields.io/pypi/v/keys-management.svg)](https://pypi.org/project/keys-management/)
[![On Pull Request](https://github.com/nielsen-oss/keys-management/actions/workflows/pr_ci.yaml/badge.svg?branch=main)](https://github.com/nielsen-oss/keys-management/actions/workflows/pr_ci.yaml)
[![Python package](https://github.com/nielsen-oss/keys-management/actions/workflows/push_ci.yaml/badge.svg?branch=main)](https://github.com/nielsen-oss/keys-management/actions/workflows/push_ci.yaml)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Keys-management is a layer tool to ease the usage of application secret keys when the 
client's application need to meet
strict security constraints and standards such as: secret key has one specific 
use case and can be rotated anytime. 

At first, it allows defining multiple secret keys, where each key can be defined from a different source.
After keys were defined, the library helps fetch the secret key value (depends on the use case described below) and manage 
rotation when a key should be changed.
It also provides a way for clients to maintain states when some objects were encrypted 
before the application goes down
while the key can be lost or changed during the downtime.

## General Usage

```python
from keys_management import KeysManagementImpl, OnChangeKeyDefinition, SecretKeyUseCase
from unittest.mock import Mock

KEY_NAME = "my_first_key"
value_for_key_store = "value_1"

def symmetric_key_store():
    return value_for_key_store

print_mock_method = Mock()
def on_keys_change(old_key: str, new_key: str, on_change_key_definition: 
OnChangeKeyDefinition):
    print_mock_method("key_changed from {} to {}.".format(old_key, new_key))

key_definition_properties = {
    'stateless': True,
    'use_case': SecretKeyUseCase.ROUND_TRIP,
    'keep_in_cache': True
}

keys_management = KeysManagementImpl(state_repo=Mock(), crypto_tool=Mock())

keys_management.define_key(KEY_NAME, symmetric_key_store, **key_definition_properties)

keys_management.register_on_change(KEY_NAME, on_keys_change)

rv_key_value = keys_management.get_forward_path_key(KEY_NAME)  # expected "value_1"

keys_management.key_changed(KEY_NAME, "value_1", "value_2")

value_for_key_store = "value_2"  # simulate key's change

rv_key_value = keys_management.get_back_path_key(KEY_NAME)  # expected "value_1"

# after key_changed declaration, print_mock_method should be called.
print_mock_method.assert_called_once_with("key_changed from {} to {}.".format(FIRST_VALUE, SECOND_VALUE))

rv_key_value = keys_management.get_forward_path_key(KEY_NAME)  # expected "value_2"
```
## installation
```python
pip install keys-management
```
## When to use
Keys Management should be used when the contained application needs to meet some security 
constraints, but still maintain flexibility and decoupling.

### Security constraints
An application could have some security constraints in regard to using secret keys and credentials
1. Use different key for each target object or client, so in case a specific key is stolen, all other objects are kept safe.
2. Key can be changed or rotated at anytime, so fresh keys can be maintained all the time.
3. When an application is crashed or exited, the keys cannot be lost so encrypted data could be decrypted.
4. The key content should be accessed only on demand, for example it should not even exist in memory  

### Flexibility and decoupling requirements
1. Each secret key value can be originated from different source, so one can be taken from environment value, 
   configurations files, remote service and etc.
2. Secret key type such as Symmetric or Asymmetric can be used
3. Multiple worker's environment application would not lead to data loss.
4. states repo - keys and values state can be saved and restored from an external repository


## How to Manage keys rotation 
The keys store is like a proxy or helper function to get the actual values. 
Thus, the client should know when the key is going to be changed. 
In most scenarios, when an application's administrator would like to rotate the 
application keys, he would like to ensure
that the important encrypted objects that can be accessed anytime, will not be loss due the change. 
To achieve it, the administrator can register callbacks to run after keys are changed. 
Before the store is ready to be called to get the new values, KeyChanged should be called. 
After KeyChanged declared, all the callbacks are executed. 

   
## Domain terminology
|   	|   	|       |
| ---	|---	|---    |
|  **SecretKeyUseCase** 	|  The use-case type the key is used for | <ul><li>ONE_WAY_TRIP - a case involve single flows like authentication </li><li>ROUND_TRIP - a case involve two flows like encryption-decryption</li></ul> |
|  **SecretKeyFlow**        |  Specific use-cases operation, a path involved in the use-case |  <ul><li>DEFAULT - the single ONE_WAY_TRIP's flow </li> <li> FORWARD_PATH - the first ROUND_TRIP's flow like encryption </li> <li> BACK_PATH - the second ROUND_TRIP's flow like decryption | 
|  **SecretKeyValue**	    | A single key value wrapper that expose the value as the real value or as censored so can be used  for logging and debugging |  `"str_value" ` <br> ` b'bytes_value'`|
|  **SecretKeyPair** 	    |  RoundTrip case involve two flows, each of them can use different value, so those values are related each other. Symmetric key, can be represented as a single value or tuple of two same values 	| `("forward_key_path", "back_key_path")` <br> `("symmetric_val", "symmetric_val")`|
|  **KeysStore**	        |  A function without arguments that its jobs to return a SecretKeyPairValues of specific target 	|<code> &nbsp;def symmetric_key_store():&nbsp;&nbsp;&nbsp;<br />&nbsp; &nbsp; return "key_value"  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</code> <br /> <code> &nbsp;def symmetric_pair_key_store():&nbsp;&nbsp;&nbsp;<br />&nbsp; &nbsp; return "key_value", "key_value" &nbsp;&nbsp;&nbsp;</code> <br /> <code> &nbsp;def asymmetric_keys_store():&nbsp;&nbsp;&nbsp;<br />&nbsp; &nbsp; return "forward_value", "back_value" &nbsp;&nbsp;&nbsp;</code> |
|  **SecretKeyState**     	|  The key's last flow is used with, and its previous SecretKeyPair  	|
|  **KeyChangedCallback** 	|  A callback that called with the old and new keys and OnChangeKeyDefinition when a key is declared as changed 	| <code> &nbsp;def on_keys_change(old_keys, new_keys, on_change_key_definition): <br /> &nbsp; print("key_changed") &nbsp;&nbsp;
|  **OnChangeKeyDefinition**|  A SecretKeyState wrapper with read access to the original key_definition  	|
|  **OnKeyChangedCallback ErrorStrategy** 	|  Which strategy should be operated on error.  | <ul> <li> RAISE_IMMEDIATELY - Raise the error immediately </li> <li> SKIP_AND_RAISE - skip to next callback, but in the end raise an error </li> <li> SKIP - skip to next callback </li> <li>HALT - Halt callback executions without raising an error </li> </ul>
|  **SecretKeyDefinition**  |  Set of key,values properties describing specific secret key, how it should be used and maintained | <ul><li> store - the key's keysStore </li> <li> use_case </li> <li> stateless - whether the key should be stated or not in the defined states' repository </li> <li> keep_in_cache - whether the key should be stated or not in the memory </li> </ul>
|  **CallbackStatus**       |   KeyChangedCallback status execution | PENDING, IN_PROGRESS, FAILED & SUCCEEDED	|
|  **StateRepoInterface**	|   A KeysManagement dependency, responsible to fetch and write keys states 	|
|  **CryptoTool**	        |   A KeysManagement dependency, responsible to decrypt and encrypt keys states 	|



## Dependencies
### StateRepoInterface
In order to maintain the keys states, an StateRepoInterface implementation should be 
injected to KeysManagement.  

```python
class StateRepoInterface(object):
    def write_state(self, key: str, key_state: Any) -> None:
        raise NotImplementedError()

    def read_state(self, key: str) -> Dict:
        raise NotImplementedError()
```

### CryptoTool
In order to maintain the keys states with confidentiality manner, a CryptoTool interface 
implementation should be injected to KeysManagement.  

```python
class CryptoTool(object):
    def encrypt(self, data: Any) -> Any:
        raise NotImplementedError()

    def decrypt(self, encrypted_data: Any) -> Any:
        raise NotImplementedError()
```

* note! - a cryptoTool eventually will need a secret key too, so think how can u use 
  the KeysManagement to help the cryptoTool help the KeysManagement



## Examples
To understand the logic behind the examples read the advanced section.  
  * application lifetime - the time when an application is going up until it is exited 
    or crashed  
      
For all example it assumed that 
```python
from keys_management import (KeysManagementImpl, OnChangeKeyDefinition, 
    SecretKeyUseCase, SecretKeyFlow, StateRepoInterface, CryptoTool)

state_repo: StateRepoInterface
crypto_tool: CryptoTool

keys_management = KeysManagementImpl(state_repo=state_repo, crypto_tool=crypto_tool)

```

### Example 1 - Authentication via 3rd party client + environment based keys store 
A third party client who call a REST API with authorization access token.  
The access token are passed with the KeysManagement assistant 


```python
# 3rd_party_client.py
class ClientExample:
    def __init__(self, access_token):
        self.set_access_token(access_token)
    
    def get_data(self):
        ''' use the access token and return some data'''
        pass

    def set_access_token(self, access_token):
        self.access_token = access_token


# app.py 
from os import environ

CLIENT_ACCESS_TOKEN_ENV_VAR = "CLIENT_ACCESS_TOKEN"
CLIENT_ACCESS_TOKEN_KEY_NAME = "CLIENT_ACCESS_TOKEN"

def key_store_from_env():
    return environ.get(CLIENT_ACCESS_TOKEN_ENV_VAR)


# no need to define it with: stateless and keep_in_cache
# since it used with AUTHENTICATION use_case, no state is required
keys_managements.define_key(
    CLIENT_ACCESS_TOKEN_KEY_NAME, key_store_from_env, use_case=SecretKeyUseCase.ONE_WAY_TRIP
)


client = Client(access_token=keys_management.get_key(CLIENT_ACCESS_TOKEN_KEY_NAME))


# client object "state" the access token so key_changed should be declare to set new
# access token for using the client.
def on_client_access_token_changed(
    old_key: str, new_key: str, on_change_key_definition: OnChangeKeyDefinition
):
    client.set_access_token(new_key)

    
keys_management.register_on_change(CLIENT_ACCESS_TOKEN_KEY_NAME, on_client_access_token_changed)

first_data = client.get_data()

environ[CLIENT_ACCESS_TOKEN_ENV_VAR] = "new_access_token"

first_data = client.get_data()  # raise an error since client still use the old token

keys_management.key_changed(CLIENT_ACCESS_TOKEN_KEY_NAME, new_keys="new_token")

second_data = client.get_data() 

```

### Example 2 - High importance data + asymmetric and python module keys store based  
* use round_trip use case as encryption-decryption, stated with caching
* The data should not be lost anytime --> key should not be lost 
* The data whether is encrypted or plained is always accessible

```python

from typing import Callable, Any, NoReturn

get_example2_data = Callable[[str], Any] 
save_example2_data = Callable[[Any, str], NoReturn]
example2_data: Any

EXAMPLE2_KEY_NAME = "EXAMPLE2_DATA"  
EXAMPLE2_DATA_ENCRYPT_KEY_CONFIG_PROPERTY = "EXAMPLE2_DATA_ENCRYPT_KEY"  
EXAMPLE2_DATA_DECRYPT_KEY_CONFIG_PROPERTY = "EXAMPLE2_DATA_DECRYPT_KEY"  

import importlib

def example2_key_store_asymmetric_keys():
    # assume there is an app.config module
    import app.config as config_module

    # it should be reloaded to get the most updated values
    importlib.reload(config_module)
    return config_module.get(EXAMPLE2_DATA_ENCRYPT_KEY_CONFIG_PROPERTY), \
           config_module.get(EXAMPLE2_DATA_DECRYPT_KEY_CONFIG_PROPERTY)

keys_management.define_key(
    EXAMPLE2_KEY_NAME,
    example2_key_store_asymmetric_keys,
    stateless=False,
    keep_in_cache=True,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)

# key changed alternative one - decrypt, encrypt again and save the state
def on_example2_key_changed(
    old_keys, new_keys, on_change_key_definition: OnChangeKeyDefinition
):
    if on_change_key_definition.get_last_flow() is SecretKeyFlow.FORWARD_PATH:
        example2_data = get_example2_data(key=old_keys[1])  # decrypt with the old key
        save_example2_data(example2_data, key=new_keys[0])  # encrypt with new key
    keys_management.save_state(on_change_key_definition.name)


# key changed alternative two: only decrypt
def on_example2_key_changed2(
    old_keys, new_keys, on_change_key_definition: OnChangeKeyDefinition
):
    if on_change_key_definition.get_last_flow() is SecretKeyFlow.FORWARD_PATH:
        people_data = get_example2_data(key=old_keys[1])  # decrypt with the old key
        # since it only decrypt the data, change the data
        on_change_key_definition.set_last_flow(SecretKeyFlow.BACK_PATH)
    # here we don't save the state, our app calls save states on exit/or failures


keys_management.register_on_change(EXAMPLE2_KEY_NAME, on_example2_key_changed)
## or
keys_management.register_on_change(EXAMPLE2_KEY_NAME, on_example2_key_changed2)

## application lifetime 1:
save_example2_data(
    example2_data, key=keys_management.get_forward_path_key(EXAMPLE2_KEY_NAME)
)

## application lifetime 2:
## on first time use - key is fetched from state repository 
example2_data = get_example2_data(keys_management.get_back_path_key(EXAMPLE2_KEY_NAME))

## for some reason, the back_path_key (decrypt key) should be get again - fetched from cache
decrypt_key = keys_management.get_back_path_key(EXAMPLE2_KEY_NAME)

## after a while :
save_example2_data(
    example2_data, key=keys_management.get_forward_path_key(EXAMPLE2_KEY_NAME)
)

## once the application admin decides to the change key, declare the change (before actually it is changed)
keys_management.key_changed(
    EXAMPLE2_KEY_NAME,
    example2_key_store_asymmetric_keys(),
    ("new_encrypt_key", "new_decrypt_key"),
)

## after key changed:
example2_data = get_example2_data(keys_management.get_back_path_key(EXAMPLE2_KEY_NAME))
```



### Example 3 - Medium importance data + symmetric and python module keys store based  
* use round_trip use case as encryption-decryption, stateless with caching
* The data should not be lost on same lifetime  
* The data whether is encrypted or plained is always accessible
* without use of key_changed callbacks

```python

from typing import Callable, Any, NoReturn

get_example3_data = Callable[[str], Any] 
save_example3_data = Callable[[Any, str], NoReturn]
example3_data: Any

EXAMPLE3_KEY_NAME = "EXAMPLE3_DATA"  
EXAMPLE3_KEY_CONFIG_PROPERTY = "EXAMPLE3_DATA_KEY"


import importlib

def example3_key_store_symmetric_keys():
    # assume there is an app.config module
    import app.config as config_module

    # it should be reloaded to get the most updated values
    importlib.reload(config_module)
    return config_module.get(EXAMPLE3_KEY_CONFIG_PROPERTY)

keys_management.define_key(
    EXAMPLE3_KEY_NAME,
    example3_key_store_symmetric_keys,
    stateless=True,
    keep_in_cache=True,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)

## application lifetime 1:
save_example3_data(
    example3_data, key=keys_management.get_forward_path_key(EXAMPLE3_KEY_NAME)
)

## application lifetime 2:
## on first time use - key is fetched from key_store 
example3_data = get_example3_data(keys_management.get_back_path_key(EXAMPLE3_KEY_NAME))

## after a while:
save_example3_data(
    example3_data, key=keys_management.get_forward_path_key(EXAMPLE3_KEY_NAME)
)

## once the application admin decides to the change key, declare the change (before actually it is changed)
keys_management.key_changed(
    EXAMPLE2_KEY_NAME,
    example2_key_store_asymmetric_keys(),
    ("new_encrypt_key", "new_decrypt_key"),
)

## After the key was changed (configuration was changed) - old key fetched from cache
example3_data = get_example3_data(keys_management.get_back_path_key(EXAMPLE3_DATA))

# Whether calling for get the forward or back key - the new key is fetched

keys_management.get_back_path_key(EXAMPLE3_DATA)
```

### Example 4 - Low importance data + symmetric from external source (AWS) keys store based  
* use round_trip use case as encryption-decryption, stateless without caching
* The data can be lost 
* The data whether is encrypted or plained is always accessible
* without use of key_changed callbacks

```python

from typing import Callable, Any, NoReturn

get_example4_data = Callable[[str], Any] 
save_example4_data = Callable[[Any, str], NoReturn]
example4_data: Any

EXAMPLE4_KEY_NAME = "EXAMPLE4_DATA"  
EXAMPLE4_KEY_CONFIG_PROPERTY = "EXAMPLE3_DATA_KEY"


def example4_key_store_from_aws():
    import boto3
    sqs = boto3.resource("keys_resource")
    # here some code the fetch the key from aws 
    return key_from_aws

keys_management.define_key(
    EXAMPLE4_KEY_NAME,
    example4_key_store_from_aws,
    stateless=True,
    keep_in_cache=False,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)

# key fetched from key store
save_example4_data(
    example4_data, key=keys_management.get_forward_path_key(EXAMPLE4_KEY_NAME)
)

## key fetched from the key store and not from cache 
example4_data = get_example4_data(keys_management.get_back_path_key(EXAMPLE4_KEY_NAME))

## after a while:
save_example4_data(
    example4_data, key=keys_management.get_forward_path_key(EXAMPLE4_KEY_NAME)
)
'''
After the key is changed (aws state was changed) - we get the key from the key store
data will be lost, we had to re decrypted it before the change. 
'''
example4_data = get_example4_data(keys_management.get_back_path_key(EXAMPLE4_DATA))
```

### Example 5 - implicit use by third party library 
* use round_trip use case as encryption-decryption
* the library treats the key as symmetric type, but keys_management assist the app to 
  mimic asymmetric key as symmetric
* caching must be enabled to let the keys_management determines flow by itself   

```python
# third_party.py
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

# app.py
from os import environ

FAKE_LIBRARY_KEY_NAME = "FAKE_LIBRARY_KEY"
FAKE_LIBRARY_ENCRYPT_KEY_ENV_VAR = "FAKE_LIBRARY_ENCRYPT_KEY"
FAKE_LIBRARY_DECRYPT_KEY_ENV_VAR = "FAKE_LIBRARY_DECRYPT_KEY"

def key_store_from_env():
    return environ.get(FAKE_LIBRARY_ENCRYPT_KEY_ENV_VAR), environ.get(FAKE_LIBRARY_DECRYPT_KEY_ENV_VAR)


keys_management.define_key(
    FAKE_LIBRARY_KEY_NAME,
    key_store_from_env,
    stateless=False,
    keep_in_cache=True,
    use_case=SecretKeyUseCase.ROUND_TRIP,
)

'''
passing a proxy lambda - it use get_get instead of get_forward_path_key or get_back_path_key 
key without explicit flow. 
''' 
library = ThirdPartyLibrary(lambda: keys_management.get_key(FAKE_LIBRARY_KEY_NAME))


'''
application lifetime 1:
keys-management determine the flow and will return the forward_path key.
'''
library.create_data()


'''
application lifetime 2:
keys-management determine the flow and will return the back_path key.
'''
library.get_data()


# keys-management determine the flow and will return the forward_path key.
library.create_data()
```

# Advanced details 

## Why to use
There are few reasons why to use a secret key: 
1. Encryption-Decryption - When we would like to achieve data confidentiality, secret keys are processed to encrypt and 
   decrypt the data. one key is for encryption and one for decryption. As opposed to using an asymmetric-key algorithm
   so the encryption and decryption keys are different, with Symmetric-key algorithm, the encryption and decryption keys
   are the same, but the keys still can be referred to as one single key for both purposes or as pair with the 
   same values. the questions that arise are what happens when the decrypt key is changed before the data is decrypted 
   and when the client detects the key was changed but its data can't be accessed immediately, 
   how the client manage rotation? 
2. Authentication, Authorization & Accountability - Whether the secret key is used for signing the data, 
   authenticate other users or sending our credentials like a password, the type of the key (password, symmetric or 
   asymmetric) doesn't really matter since only one key is playing the role of process.
   
   
## key internal flows 

The key definitions properties effect the actual value will be returned when the scenario is Encryption-Decryption and the purpose was passed to get_key.
You can pass the purpose explicit or implicit by calling get_decrypt_key/get_encrypt_key.
When the purpose is not passed, the keys management will determine by itself, based on the previous use.
When the previous keys is not defined it will try to fetch it from the states repository only when the key is defined as "stated"
otherwise it always Encryption.

After current purpose is determined, 
   * Encryption - the keys always taken from the store
   * Decryption - based on how the key was defined:  
      &nbsp;&nbsp;if decrypt keys already taken and kept in cache  
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;__note__ - *remember when keep_in_cache is False, the keys that taken from store does not kept.*  
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;it will take the last decrypt key  
      &nbsp;&nbsp;but if not and the key defined as "stated",  
     &nbsp;&nbsp;&nbsp;&nbsp;it will first try to take it from the states repository.   
      &nbsp;&nbsp;otherwise - from the store. 

   Button line - when the key is changed, but it defined to keep in cache, keys management helps you not losing the encrypted objects since the it keep the last decrypt key!  
If the keys marked as "stated" and it is important for the client to maintains the state in the repository, it should call the save state immediate after getting the key. 

