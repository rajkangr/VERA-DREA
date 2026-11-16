import ipaddress
import socket
from urllib.parse import urlparse

def validate_webhook_target(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return False
    ip_str = socket.gethostbyname(parsed.hostname)
    ip_obj = ipaddress.ip_address(ip_str)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return False
    return True
