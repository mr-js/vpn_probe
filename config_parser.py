import base64
import json
import logging
from urllib.parse import urlparse, unquote

def get_vmess_host_port(link):
    try:
        json_str = base64.b64decode(link[8:] + '===').decode('utf-8')
        data = json.loads(json_str)
        return data.get('add'), data.get('port')
    except Exception as e:
        logging.error(f"Error parsing VMess host/port: {e}")
        return None, None

def get_vless_host_port(link):
    try:
        parsed = urlparse(link)
        return parsed.hostname, parsed.port
    except Exception as e:
        logging.error(f"Error parsing VLESS host/port: {e}")
        return None, None

def get_trojan_host_port(link):
    try:
        parsed = urlparse(link)
        return parsed.hostname, parsed.port
    except Exception as e:
        logging.error(f"Error parsing Trojan host/port: {e}")
        return None, None

def get_ss_host_port(link):
    try:
        parsed = urlparse(link)
        return parsed.hostname, parsed.port
    except Exception as e:
        logging.error(f"Error parsing Shadowsocks host/port: {e}")
        return None, None

def get_v2ray_config_data(link):
    try:
        parsed_url = urlparse(link)
        params = {
            k: v for k, v in (
                param.split('=', 1) if '=' in param else (param, '')
                for param in parsed_url.query.split('&')
            )
            if k
        }

        if link.startswith("vmess://"):
            json_str = base64.b64decode(link[8:] + '===').decode('utf-8')
            data = json.loads(json_str)
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": data.get("add"),
                            "port": int(data.get("port", 0)),
                            "users": [
                                {
                                    "id": data.get("id"),
                                    "alterId": int(data.get("aid", 0)),
                                    "security": data.get("scy", "auto")
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": data.get("net", "tcp"),
                    "security": data.get("tls", ""),
                },
                "tag": "proxy"
            }
            if outbound["streamSettings"].get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": data.get("host", data.get("add", ""))
                }
            if outbound["streamSettings"].get("network") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": data.get("path", ""),
                    "headers": {"Host": data.get("host", data.get("add", ""))}
                }
            if outbound["streamSettings"].get("network") == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": data.get("path", "")
                }

        elif link.startswith("vless://"):
            # Улучшения для VLESS
            username = parsed_url.username
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": parsed_url.hostname,
                            "port": parsed_url.port,
                            "users": [
                                {
                                    "id": username,
                                    "encryption": "none",
                                    "flow": params.get("flow", "")
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": params.get("security", "none"),
                },
                "tag": "proxy"
            }
            # Поддержка Reality
            if outbound["streamSettings"].get("security") == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": params.get("sni", parsed_url.hostname),
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk", ""),
                    "shortId": params.get("sid", ""),
                    "spiderX": params.get("spx", "")
                }
            # Поддержка TLS
            elif outbound["streamSettings"].get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get("sni", parsed_url.hostname),
                    "allowInsecure": params.get("allowInsecure", "false") == "true"
                }
            # Поддержка WebSocket
            if outbound["streamSettings"].get("network") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": params.get("path", ""),
                    "headers": {"Host": params.get("host", parsed_url.hostname)}
                }
            # Поддержка gRPC
            if outbound["streamSettings"].get("network") == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": params.get("serviceName", params.get("path", "")),
                    "multiMode": params.get("mode", "multi")
                }

        elif link.startswith("trojan://"):
            # Улучшения для Trojan
            outbound = {
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": parsed_url.hostname,
                            "port": parsed_url.port,
                            "password": parsed_url.username,
                            "level": int(params.get("level", 0))
                        }
                    ]
                },
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": params.get("security", "none"),
                },
                "tag": "proxy"
            }
            # Поддержка TLS
            if outbound["streamSettings"].get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get("sni", parsed_url.hostname),
                    "allowInsecure": params.get("allowInsecure", "false") == "true"
                }
            # Поддержка WebSocket
            if outbound["streamSettings"].get("network") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": params.get("path", ""),
                    "headers": {"Host": params.get("host", parsed_url.hostname)}
                }
            # Поддержка gRPC
            if outbound["streamSettings"].get("network") == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": params.get("serviceName", params.get("path", "")),
                    "multiMode": params.get("mode", "multi")
                }

        elif link.startswith("ss://"):
            # Улучшения для Shadowsocks
            method_password = parsed_url.netloc
            if '@' in method_password:
                method_password = method_password.split('@')[0]
            method, password = method_password.split(':', 1) if ':' in method_password else (method_password, '')
            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": parsed_url.hostname,
                            "port": parsed_url.port,
                            "method": method,
                            "password": unquote(password),
                            "level": int(params.get("level", 0))
                        }
                    ]
                },
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": params.get("security", "none"),
                },
                "tag": "proxy"
            }
            # Поддержка gRPC
            if outbound["streamSettings"].get("network") == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": params.get("serviceName", params.get("path", "")),
                    "multiMode": params.get("mode", "multi")
                }
            # Поддержка TLS (если используется обертка)
            if outbound["streamSettings"].get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get("sni", parsed_url.hostname),
                    "allowInsecure": params.get("allowInsecure", "false") == "true"
                }

        else:
            return None

        # Базовая конфигурация Xray
        config = {
            "inbounds": [
                {
                    "protocol": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": 1080,
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"]
                    }
                }
            ],
            "outbounds": [
                outbound,
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"}
            ],
            "dns": {
                "servers": ["8.8.8.8", "1.1.1.1"],
                "disableFallback": True
            },
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["socks-in"],
                        "port": 53,
                        "outboundTag": "dns-out"
                    },
                    {
                        "type": "field",
                        "outboundTag": "proxy",
                        "port": "0-65535"
                    }
                ]
            }
        }
        return config

    except Exception as e:
        logging.error(f"Error parsing link {link}: {e}")
        return None
