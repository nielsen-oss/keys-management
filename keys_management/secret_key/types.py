from typing import Union, Tuple, Dict, Callable

SecretKeyValue = Union[str, bytes]
SecretKeyPairValues = Union[
    SecretKeyValue,
    Tuple[SecretKeyValue, SecretKeyValue],
    Dict[str, SecretKeyValue],
]
KeysStore = Callable[[], SecretKeyPairValues]
