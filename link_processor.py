import re
from config_parser import get_vmess_host_port, get_vless_host_port, get_trojan_host_port, get_ss_host_port

def get_host_port(link):
    if link.startswith("vmess://"):
        return get_vmess_host_port(link)
    elif link.startswith("vless://"):
        return get_vless_host_port(link)
    elif link.startswith("trojan://"):
        return get_trojan_host_port(link)
    elif link.startswith("ss://"):
        return get_ss_host_port(link)
    return None, None
