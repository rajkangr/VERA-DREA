from net_utils import dispatch_webhook

def register_and_ping_webhook(payload):
    callback_url = payload.get('callback_url', '')
    return dispatch_webhook(callback_url, {'status': 'ok'})
