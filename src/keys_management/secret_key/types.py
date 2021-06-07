from typing import Callable, Tuple, Union

SecretKeyValue = Union[str, bytes]
SecretKeyPairValues = Tuple[SecretKeyValue, SecretKeyValue]
KeysStore = Callable[[], Union[SecretKeyValue, SecretKeyPairValues]]
