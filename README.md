# keys-management
pip package: https://pypi.org/project/keys-management/

[![image](https://img.shields.io/pypi/v/keys-management.svg)](https://pypi.org/project/keys-management/)
[![On Pull Request](https://github.com/nielsen-oss/keys-management/actions/workflows/pr_ci.yaml/badge.svg?branch=main)](https://github.com/nielsen-oss/keys-management/actions/workflows/pr_ci.yaml)
[![Python package](https://github.com/nielsen-oss/keys-management/actions/workflows/push_ci.yaml/badge.svg?branch=main)](https://github.com/nielsen-oss/keys-management/actions/workflows/push_ci.yaml)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

keys-managemet is a layer tool to ease the usage of application secret keys when the client's application need to meet
strict security constraints and standards for example: secret key has one specific use case and can be rotated anytime. 

At first, it allows defining multiple secret keys, where each key can be defined from a different source.
After keys were defined, the library helps fetch the secret key value (depends on the use case described below) and manage 
rotation when a key is changed.
It also provides a way for clients to maintain a state when some objects were encrypted before the application goes down
while the key can be lost or changed during the downtime.

### General Usage

```python
from keys_management import KeysManagementImpl, OnChangeKeyDefinition, SecretKeyUseCase
from unittest.mock import Mock

print_mock = Mock()

KEY_NAME = 'my_first_key'
FIRST_VALUE = 'value_1'
SECOND_VALUE = 'value_2'
current_value = FIRST_VALUE

def key_store():
    return current_value

def on_change(old_key: str, new_key: str, on_change_key_definition: OnChangeKeyDefinition):
    print_mock("key_changed from {} to {}.".format(old_key, new_key))

key_definition_properties = {
    'stateless': True,
    'use_case': SecretKeyUseCase.ENCRYPTION_DECRYPTION,
    'target_data_accessible': True,
    'keep_in_cache': True
}
```
Create the keys management
```python
keys_management = KeysManagementImpl(state_repo=Mock(), crypto_tool=Mock())
```

Define key

```python
keys_management.define_key(KEY_NAME, key_store, **key_definition_properties)
keys_management.register_on_change(KEY_NAME, on_change)
```

Get and declare on key changes
```python
assert keys_management.get_key(KEY_NAME) == FIRST_VALUE
current_value = SECOND_VALUE
keys_management.key_changed(KEY_NAME, FIRST_VALUE, SECOND_VALUE)
print_mock.assert_called_once_with("key_changed from {} to {}.".format(FIRST_VALUE, SECOND_VALUE))
assert keys_management.get_key(KEY_NAME) == SECOND_VALUE
```

# When to use
Keys Management should be used when the host application needs to meet some security constraints, but still maintain flexibility and decoupling.

## Security constraints
An application could have some security constraints in regards to using secret keys and credentials
1. Use different key for each target object or client, so in case a specific key is stolen, all other objects are kept safe.
2. Key can be changed or rotated at anytime, so fresh keys can be maintained all the time.
3. When an application is crashed or exited, the keys cannot be lost so encrypted data could be decrypted.
4. The key content should be accessed only on demand, for example it should not even exist in memory  

## Flexibility and decoupling requirements
1. Each secret key value can be originated from different source, so one can be taken from environment value, 
   configurations files, remote service and etc.
2. Secret key type such as Symmetric or Asymmetric can be used
3. Multiple worker's environment application would not lead to data loss.
4. states repo - keys and values state can be saved and restored from an external repository


# How to Manage keys rotation 
The keys store is like a proxy or helper function to get the actual values. 
Thus, the client should know when the key is going to be changed. 
In most scenarios, when an application's administrator would like to rotate the application keys, he would like to insure
that the important encrypted objects that can be accessed anytime, will not be loss due the change. 
Thus, the administrator can register callbacks to run after keys are changed. 
Before the store is ready to be called to get the new values, KeyChanged should be called. 
After KeyChanged declared, all the callbacks are executed. 

   
# Domain terminology
|   	|   	|
|---	|---	|
|  **SecretKeyUseCase** 	|  The specific use-case the key is used for: encryption, decryption or AAA (Authentication, Authorization & Accountability) 	|
|  **SecretKeyValue** 	    |  Key's content, the actual concrete value and its type is string or bytes 	|
|  **SecretKey**	        |  A single SecretKeyValue wrapper that expose the value as the real value or as censored so can be used for logging and debugging 	|
|  **SecretKeyPairValues** 	|  As describe in encryption-decryption above, two keys values related to each other. as describe above, in the case of symmetric key, it can be represented as a single key or two same values, so the actual object type can be a single value or as a tuple 	|
|  **SecretKeyPair** 	    |  A wrapper of two SecretKey, related each other 	|
|  **keysStore**	        |  A function without arguments that its jobs to return a SecretKeyPairValues of specific target 	|
|  **SecretKeyState**     	|  For specific defined key, what was the previous use case is used for, and its previous SecretKeyPairValues 	|
|  **KeyChangedCallback** 	|  A callback (function) that called when a key is declared that it's values were changed. the callback is called with the old and new keys and OnChangeKeyDefinition 	|
|  **OnChangeKeyDefinition**|  A SecretKeyState wrapper with read access to the original key_definition  	|
|  **OnKeyChangedCallbackErrorStrategy** 	|  Which strategy should be operated on error. <br> - RAISE_IMMEDIATELY <br>- Raise the error immediately <br>- SKIP_AND_RAISE <br>- Skip to next callback, but in the end raise an error <br>- SKIP - Skip to next callbac <br>- HALT - Halt callback executions without raising an error  |
|  **SecretKeyDefinition**  |   set of key,values properties describing specific secret key, how it should be used and maintained<br>- store  - It's specific keysStore<br>- use_case  	-   What is the main purpose/senario/use-case. there are two options: Encryption-Decryption or AAA<br>- stateless  -   ndication if the key should be stated or not in the defined states' repository <br>- target_data_accessible -  Indication if the target data/object/client the key is processed on, can be access by the client whenever it required<br>- keep_in_cache |Indication if the key should be stated or not in the memory or any other cache tool |
|  **CallbackStatus**       |   KeyChangedCallback status execution: PENDING, IN_PROGRESS, FAILED and SUCCEEDED	|
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
### Authtication to third_party client
Assume there is a third_party client called 3p_client 

```python
# 3p_client package
class Client:
    def __init__(self, access_token):
        self.set_access_token(access_token)
    
    def get_data(self):
        ''' use the access token and return some data'''
        pass

    def set_access_token(self, access_token):
        self.access_token = access_token
```
Inside the app initialization

```python
import keys_management
from os import environ

CLIENT_ACCESS_TOKEN = "CLIENT_ACCESS_TOKEN"


def ket_from_env():
    return environ.get(CLIENT_ACCESS_TOKEN)


keys_management.define_key(CLIENT_ACCESS_TOKEN, ket_from_env,
                           use_case=SecretKeyUseCase.AUTHENTICATION)

from 3p_client import Client

client = Client(access_token=keys_management.get_key(CLIENT_ACCESS_TOKEN))

def on_client_access_token_changed(old_key: str, new_key: str, on_change_key_definition: OnChangeKeyDefinition)
    client.set_access_token(new_key)
    on_change_key_definition.



```

# Advanced

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

