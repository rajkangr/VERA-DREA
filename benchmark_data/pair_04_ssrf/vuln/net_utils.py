import urllib.request
from url_policy import validate_webhook_target

def dispatch_webhook(url, data):
    if not validate_webhook_target(url):
        raise ValueError('Blocked webhook URL')
    req = urllib.request.Request(url, method='POST')
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.status
