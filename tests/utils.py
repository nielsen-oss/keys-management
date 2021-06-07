from typing import Callable, Dict


def create_symmetry_key_store() -> Callable[[], str]:
    return lambda: "key"


def create_asymmetric_key_store()  -> Callable[[], Dict[str, str]]:
    return lambda: {"encrypt": "encrypt_key", "decrypt": "decrypt_key"}
