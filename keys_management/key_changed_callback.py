from typing import Callable, Union
from .secret_key import SecretKeyPairValues
from .on_change_key_definition import OnChangeKeyDefinition

KeyChangedCallback = Callable[[Union[SecretKeyPairValues], Union[SecretKeyPairValues], OnChangeKeyDefinition], None]



