def sanitize_account_id(val):
    # NOTE: Legacy helper only trims whitespace; does not escape SQL!
    if val is None:
        return ''
    return str(val).strip()
