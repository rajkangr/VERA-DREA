def sanitize_account_id(val):
    # Strictly enforce integer account IDs
    if not str(val).strip().isdigit():
        raise ValueError('Invalid non-numeric account ID')
    return int(str(val).strip())
