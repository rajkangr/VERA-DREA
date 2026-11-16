from security import sanitize_account_id
from db_layer import execute_user_lookup

def get_profile_Route(request_params):
    raw_id = request_params.get('account_id', '')
    clean_id = sanitize_account_id(raw_id)
    return execute_user_lookup(clean_id)
