# keys-management
pip package: https://pypi.org/project/keys-management/

[![On Pull Request](https://github.com/nielsen-oss/keys-management/actions/workflows/pr_ci.yaml/badge.svg?branch=main)](https://github.com/nielsen-oss/keys-management/actions/workflows/pr_ci.yaml)
[![Python package](https://github.com/nielsen-oss/keys-management/actions/workflows/push_ci.yaml/badge.svg?branch=main)](https://github.com/nielsen-oss/keys-management/actions/workflows/push_ci.yaml)

KeysManagemets is a layer tool to ease the usage of application secret keys when the client's application need to meet
strict security constrains and standards such as: secret key has one specific use case and can be rotated anytime. 

At first, it allows defining multiple secret keys, when each key can be defined from different source.
After keys were defined, the library helps fetch the secret key value (depend on the use case is described below) and manage 
rotation when a key is changed.
An optional feature, it can help the client maintains a state when some objects were encrypted before application goes down
while the key can be lost or changed during the downtime.

###Basic usage

first, for the demo purpse, let define some variables
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
    'use_case': SecretKeyUseCase.AUTHENTICATION,
    'target_data_accessible': True,
    'keep_in_cache': True
}
```
init the keys management
```python
keys_management = KeysManagementImpl(state_repo=Mock(), crypto_tool=Mock())
```

define key

```python
keys_management.define_key(KEY_NAME, key_store, **key_definition_properties)
keys_management.register_on_change(KEY_NAME, on_change)
```

get and declare on key changes
```python
assert keys_management.get_key(KEY_NAME) == FIRST_VALUE
current_value = SECOND_VALUE
keys_management.key_changed(KEY_NAME, FIRST_VALUE, SECOND_VALUE)
print_mock.assert_called_once_with("key_changed from {} to {}.".format(FIRST_VALUE, SECOND_VALUE))
assert keys_management.get_key(KEY_NAME) == SECOND_VALUE
```

# When to use
Keys Management should be used when the host application should meet some security constrains, but in the other hand 
flexibility and decoupling are your guidelines 

## Security constraints
an application could have some security constrains regard using secret keys and credentials
1. Use different key for each target object or client, so in case specific key was stolen, all others objects are kept safe.
2. Key can be changed or rotated anytime, so fresh keys can be maintained all the time.
3. When an application is crashed or exited, the keys cannot be lost so encrypted data could be decrypted.
4. The key content should be accessed only on demand, for example it should not even <??> in memory  

## Flexibility and decoupling requirements
1. Each secret key value can be originated from different source, so one can be taken from environment value, 
   configurations files, remote service and etc.
2. The secret key kind such as Symmetric or Asymmetric can be ???
3. multiple worker's environment application would not lead to data loss.
4. states repo - ???

# Scenarios 
There are few reasons why to use a secret key: 
1. Encryption-Decryption: when we would like to achieve data confidentiality, secret keys are processed to encrypt and 
   decrypt the data. one key is for encryption and one for decryption. As opposed to using an asymmetric-key algorithm
   so the encryption and decryption keys are different, with Symmetric-key algorithm, the encryption and decryption keys
   are the same, but the keys still can be referred to as one single key for both purposes or as pair with the 
   same values. the questions that arise are what happens when the decrypt key is changed before the data is decrypted 
   and when the client detects the key was changed but its data can't be accessed immediately, 
   how the client manage rotation? 
2. Authentication, Authorization & Accountability - whether the secret key is used for signing the data, 
   authenticate other users or sending our credentials like a password, the type of the key (password, symmetric or 
   asymmetric) doesn't really matter since only one key is playing the role of process.
   
# Domain terminology
SecretKeyUseCase - the specific use-case the key is used for: encryption, decryption or AAA (Authentication, 
   Authorization & Accountability)
SecretKeyValue - as its name revealed, is the key's content, the actual concrete value and its type is string or bytes
SecretKey - a single SecretKeyValue wrapper that expose the value as the real value or as censored so can be used for 
   logging and debugging.
SecretKeyPairValues - as describe in encryption-decryption above, two keys values related to each other. as described
   above, in the case of symmetric key, it can be represented as a single key or two same values, 
   so the actual object type can be a single value or as a tuple.
SecretKeyPair - a wrapper of two SecretKey, related each other. 
keysStore - a function without arguments that its jobs to return a SecretKeyPairValues of specific target.  
SecretKeyState - for specific defined key, what was the previous use case is used for, and its previous SecretKeyPairValues
KeyChangedCallback - a callback (function) that called when a key is declared that it's values were changed. 
   the callback is called with the old and new keys and OnChangeKeyDefinition
OnChangeKeyDefinition -  a SecretKeyState wrapper with read access to the original key_definition  

OnKeyChangedCallbackErrorStrategy - as its name revealed what strategy should be operated on error.
   RAISE_IMMEDIATELY - raise the error immediately 
   SKIP_AND_RAISE - skip to next callback, but in the end raise an error
   SKIP = skip to next callback
   HALT = halt callback executions without raising an error 

SecretKeyDefinition - set of key,values properties describing specific secret key, how it should be used and maintained.
   store - it's specific keysStore.
   use_case - what is the main purpose/senario/use-case. there are two options: Encryption-Decryption or AAA
   stateless - indication if the key should be stated or not in the defined states' repository
   target_data_accessible - indication if the target data/object/client the key is processed on, can be access by the 
      client whenever it required.
   keep_in_cache - indication if the key should be stated or not in the memory or any other cache tool.
CallbackStatus - KeyChangedCallback status execution: PENDING, IN_PROGRESS, FAILED and SUCCEEDED

StateRepoInterface - TODO
CryptoTool = TODO 


#flows 

the key definitions properties effect the actual value will be returned when the use-case is Encryption-Decryption and the purpose was passed to get_key.
you can pass the purpose explicit or implicit by calling get_decrypt_key/get_encrypt_key.
when the purpose is not passed, the keys management will determine by itself, based on the previous use.
when the previous keys is not defined it will try to fetch it from the states repository only when the key is defined as "stated"
otherwise it always Encryption.

After current purpose is determined, 
   encryption - the keys always taken from the store
   decryption - based on how the key was defined:
      if decrypt keys already taken and kept in cache
         note - remember when keep_in_cache is False, the keys that taken from store does not kept. 
         it will take the last decrypt key
      but if not and the key defined as "stated", it will first try to take it from the states repository. 
      otherwise - from the store. 

   button line - when the key is changed, but it defined to keep in cache, keys management helps you not losing the encrypted objects since the it keep the last decrypt key!

if the keys marked as "stated" and it is important for the client to maintains the state in the repository, it should call the save state immediate after getting the key. 

# keys rotation 
the keys store is like a proxy or an helper function to get the actual values. thus, the client should know when the key is goning to be changed. 
in most senarios, when an application's administrator would like to rotate the application keys, he would like to insure
all of the important encrypted objects that can be accessed anytime, will not be loss due the change. 
thus, the administrator can register callbacks to run after keys are changed. 
before the store is ready to be called to get the new values, KeyChanged should be called. 
after KeyChanged declared, all the callbacks are executed. 




