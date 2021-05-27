def create_symmetry_key_store():
    return lambda: 'key'


def create_asymmetric_key_store():
    return lambda: {'encrypt': 'encrypt_key', 'decrypt': 'decrypt_key'}
