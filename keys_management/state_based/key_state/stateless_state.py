from typing import Dict

from ..key_state import OneState
from ..consts import TEMP_STATE_NAME
from ...secret_key import SecretKeyUseCase
from ...consts import STATE


class StatelessState(OneState):
    def __init__(self):
        super(StatelessState, self).__init__()

    def get_use_case(self) -> SecretKeyUseCase:
        return SecretKeyUseCase.ENCRYPTION_DECRYPTION

    def get_name(self) -> str:
        return TEMP_STATE_NAME

    def to_dict(self) -> Dict:
        return {STATE: TEMP_STATE_NAME}
