from typing import Dict
from ..consts import AUTHENTICATION_STATE
from ..key_state import OneState
from ...secret_key import SecretKeyUseCase
from ...consts import STATE


class AuthenticationState(OneState):
    def __init__(self):
        super(AuthenticationState, self).__init__()

    def get_use_case(self) -> SecretKeyUseCase:
        return SecretKeyUseCase.AUTHENTICATION

    def get_name(self) -> str:
        return AUTHENTICATION_STATE

    def to_dict(self) -> Dict:
        return {STATE: AUTHENTICATION_STATE}
