from logging import DEBUG

KEEP_STATE = "keep_state"
KEY = "key"
STATE = "state"
KEYS_STORE = "keys_store"
FORWARD_PATH_FLOW_STATE = "forward"
ENCRYPTED_STATE = "forward"
BACK_PATH_FLOW_STATE = "back"
DECRYPTED_STATE = "back"
ENCRYPTION_KEY_TYPE = "encrypt"
DECRYPTION_KEY_TYPE = "decrypt"
PUBLIC_KEY_TYPE = "public"
PRIVATE_KEY_TYPE = "private"
ON_CHANGES_CALLBACKS = "callback"


DEFINE_KEY_LOG_MESSAGE = 'Defining the key "%s"'
DEFINE_KEY_DEBUG_MESSAGE = "New key was defined %s"


GET_KEY_INFO_MESSAGE = 'requested to get key of "{}"'
GET_KEY_DEBUG_MESSAGE = 'requested to get key of "{}" for {}'
LOG_GEY_DEBUG_MESSAGE = 'rv_key is "%s"'
KEY_CHANGED_DEBUG_MESSAGE = (
    'the key "{}" is changed from {} to {} registered callbacks will be executed'
)
KEY_CHANGED_INFO_MESSAGE = (
    'the key "{}" is changed, registered callbacks will be executed'
)
REGISTER_ON_CHANGE_LOG_MESSAGE = 'registering new OnChange callback for "%s"'

TRACE_LEVEL = DEBUG - 1
TRACE_LEVEL_NAME = "TRACE"
