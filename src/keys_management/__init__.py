from typing import TYPE_CHECKING
from .dependecies import CryptoTool, StateRepoInterface
from .errors import (
    GetKeyError,
    KeyChangedError,
    KeyIsNotDefinedError,
    KeysManagementError,
)
from .key_changed_utils import OnKeyChangedCallbackErrorStrategy
from .keys_management import KeysManagement, KeysManagementImpl
from .on_change_key_definition import (
    OnChangeKeyDefinition,
    OnChangeKeyDefinitionInitError,
)
from .secret_key import (
    BaseSecretKeyDefinition,
    InvalidFlowNameError,
    SecretKeyDefinitionInitError,
    SecretKeyFlow,
    SecretKeyUseCase,
)

if TYPE_CHECKING:
    from .key_changed_utils import KeyChangedCallback
    from .secret_key import KeysStore, StrOrBytes, StrOrBytesPair
