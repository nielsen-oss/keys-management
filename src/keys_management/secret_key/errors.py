from ..errors import KeysManagementError


class InitError(KeysManagementError):
    def __init__(self, what_to_init: str, why: str) -> None:
        super().__init__(
            "Failed to init {what_to_init}: {why}".format(
                what_to_init=what_to_init, why=why
            )
        )
