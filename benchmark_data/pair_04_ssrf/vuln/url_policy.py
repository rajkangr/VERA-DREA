from urllib.parse import urlparse

def validate_webhook_target(url):
    parsed = urlparse(url)
    # Vulnerable: only blocks literal 'localhost', allows 127.0.0.1 and 169.254.169.254
    if parsed.scheme not in ('http', 'https'):
        return False
    if parsed.hostname == 'localhost':
        return False
    return True
