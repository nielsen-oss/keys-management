from typing import Callable, Tuple, Union

StrOrBytes = Union[str, bytes]
StrOrBytesPair = Tuple[StrOrBytes, StrOrBytes]
KeysStore = Callable[[], Union[StrOrBytes, StrOrBytesPair]]
