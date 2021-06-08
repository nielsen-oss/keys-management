DEFINE_KEY_LOG_FORMAT = 'Defining the key "%s"'
SUCCESS_DEFINE_KEY_LOG_FORMAT = "New key was defined %s"

GET_KEY_INFO_FORMAT = 'requested to get key of "{}"'
GET_KEY_DEBUG_FORMAT = 'requested to get key of "{}" for {}'
RV_KEY_LOG_FORMAT = 'rv_key is "%s"'
KEY_CHANGED_INFO_FORMAT = (
    'the key "{}" is changed, registered callbacks will be executed'
)
KEY_CHANGED_DEBUG_FORMAT = (
    'the key "{}" is changed from {} to {} registered callbacks will be executed'
)
REGISTER_ON_CHANGE_LOG_FORMAT = 'registering new OnChange callback for "%s"'

ON_SKIP_LOG_FORMAT = 'Skip to next onChange callbacks execution of "{key_name}": Failed to execute {callback_name} - {error}'
ON_HALT_LOG_FORMAT = 'Halt onChange callbacks execution of "{key_name}": Failed to execute {callback_name} - {error}'
CLEAN_PREV_KEYS_LOG_FORMAT = "clean previous '%s' keys from cache"
CLEAN_KEYS_LOG_FORMAT = "clean '%s' keys from cache"
