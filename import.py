import json
import base64
import logging
import os
from urllib.parse import urlparse, unquote
import uuid
import sys
import socket
import ipaddress
import time
import requests  # pip install requests

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Функция для проверки, является ли строка валидным IP
def is_valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

# Функция для получения кода страны по IP через ip-api.com
def get_country_from_ip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            country_code = data.get("countryCode")
            if country_code:
                logging.info(f"GeoIP API: {ip} -> {country_code}")
                return country_code
            else:
                logging.warning(f"GeoIP API: No country for {ip}")
                return None
        else:
            logging.warning(f"GeoIP API error for {ip}: Status {response.status_code}")
            return None
    except Exception as e:
        logging.warning(f"GeoIP API request failed for {ip}: {e}")
        return None

# Функция для получения флага страны по ISO коду
def country_to_flag(country_code):
    if not country_code:
        return ""
    return ''.join(chr(ord(c) + 0x1F1A5) for c in country_code.upper()) + " "

# Функции для парсинга host/port (без изменений)
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

# Функция для создания bean и type на основе ссылки (без изменений, из предыдущей версии)
def get_nekoray_profile(link, profile_name):
    try:
        parsed_url = urlparse(link)
        params = {
            k: v for k, v in (
                param.split('=', 1) if '=' in param else (param, '')
                for param in parsed_url.query.split('&')
            )
            if k
        }

        bean = {
            "_v": 0,
            "addr": "",
            "brutal_speed": 0,
            "c_cfg": "",
            "c_out": "",
            "enable_brutal": False,
            "mux": 0,
            "name": profile_name,
            "port": 0,
            "stream": {
                "alpn": "",
                "cert": "",
                "ed_len": 0,
                "ed_name": "",
                "h_type": "",
                "headers": "",
                "host": "",
                "insecure": False,
                "method": "",
                "net": "tcp",
                "pac_enc": "",
                "path": "",
                "pbk": "",
                "sec": "",
                "sid": "",
                "sni": "",
                "utls": ""
            }
        }

        protocol_type = ""

        if link.startswith("vmess://"):
            protocol_type = "vmess"
            json_str = base64.b64decode(link[8:] + '===').decode('utf-8')
            data = json.loads(json_str)
            bean["addr"] = data.get("add", "")
            bean["aid"] = int(data.get("aid", 0))
            bean["id"] = data.get("id", "")
            bean["port"] = int(data.get("port", 0))
            bean["sec"] = data.get("scy", "auto")
            stream = bean["stream"]
            stream["net"] = data.get("net", "tcp")
            stream["sec"] = data.get("tls", "")
            stream["host"] = data.get("host", "")
            stream["path"] = data.get("path", "")
            if stream["sec"] == "tls":
                stream["sni"] = data.get("host", data.get("add", ""))
                if "alpn" in data:
                    stream["alpn"] = data.get("alpn", "")
            if stream["net"] == "tcp":
                stream["h_type"] = data.get("type", "")
            if stream["net"] == "ws":
                stream["host"] = data.get("host", data.get("add", ""))
                if "headers" in data:
                    stream["headers"] = data.get("headers", "")
            if stream["net"] == "grpc":
                stream["ed_name"] = data.get("path", "")
                stream["path"] = data.get("path", "")

        elif link.startswith("vless://"):
            protocol_type = "vless"
            username = parsed_url.username
            bean["addr"] = parsed_url.hostname
            bean["port"] = parsed_url.port
            bean["pass"] = username
            bean["flow"] = params.get("flow", "")
            stream = bean["stream"]
            stream["net"] = params.get("type", "tcp")
            stream["sec"] = params.get("security", "none")
            stream["sni"] = params.get("sni", parsed_url.hostname)
            stream["insecure"] = params.get("allowInsecure", "false") == "true"
            if stream["sec"] == "reality":
                stream["pbk"] = params.get("pbk", "")
                stream["sid"] = params.get("sid", "")
                stream["utls"] = params.get("fp", "chrome")
                stream["pac_enc"] = "xudp" if bean.get("flow", "") == "xtls-rprx-vision" else ""
            elif stream["sec"] == "tls":
                stream["alpn"] = params.get("alpn", "")
                stream["utls"] = params.get("fp", "")
            if stream["net"] == "tcp":
                stream["h_type"] = params.get("headerType", "")
            if stream["net"] == "ws":
                stream["path"] = params.get("path", "")
                stream["host"] = params.get("host", parsed_url.hostname)
            if stream["net"] == "grpc":
                stream["ed_name"] = params.get("serviceName", params.get("path", ""))
                stream["path"] = params.get("serviceName", params.get("path", ""))
            if bean.get("flow", "") == "xtls-rprx-vision":
                stream["pac_enc"] = "xudp"

        elif link.startswith("trojan://"):
            protocol_type = "trojan"
            bean["addr"] = parsed_url.hostname
            bean["port"] = parsed_url.port
            bean["pass"] = parsed_url.username
            stream = bean["stream"]
            stream["net"] = params.get("type", "tcp")
            stream["sec"] = params.get("security", "none")
            stream["sni"] = params.get("sni", parsed_url.hostname)
            stream["insecure"] = params.get("allowInsecure", "false") == "true"
            if stream["sec"] == "tls":
                stream["alpn"] = params.get("alpn", "")
                stream["utls"] = params.get("fp", "")
            if stream["net"] == "tcp":
                stream["h_type"] = params.get("headerType", "")
            if stream["net"] == "ws":
                stream["path"] = params.get("path", "")
                stream["host"] = params.get("host", parsed_url.hostname)
            if stream["net"] == "grpc":
                stream["ed_name"] = params.get("serviceName", params.get("path", ""))
                stream["path"] = params.get("serviceName", params.get("path", ""))

        elif link.startswith("ss://"):
            protocol_type = "shadowsocks"
            authority = parsed_url.netloc
            query = parsed_url.query
            tag = unquote(parsed_url.fragment) if parsed_url.fragment else ""
            plugin_params = dict(p.split('=', 1) for p in query.split('&') if p) if query else {}
            plugin = plugin_params.get("plugin", "")

            method = ""
            password = ""
            host = parsed_url.hostname
            port = parsed_url.port

            decoded_full = None
            try:
                decoded_full = base64.urlsafe_b64decode(authority + "==").decode('utf-8')
            except:
                pass

            if decoded_full and '@' in decoded_full:
                userinfo, host_port = decoded_full.split('@', 1)
                host, port_str = host_port.split(':', 1) if ':' in host_port else (host_port, "")
                port = int(port_str) if port_str else None
                if ':' in userinfo:
                    method, password = userinfo.split(':', 1)
                else:
                    method = userinfo
                    password = ""
            else:
                if '@' in authority:
                    userinfo, host_port = authority.split('@', 1)
                    host, port_str = host_port.split(':', 1) if ':' in host_port else (host_port, "")
                    port = int(port_str) if port_str else None
                    try:
                        decoded = base64.urlsafe_b64decode(userinfo + "==").decode('utf-8')
                        if ':' in decoded:
                            method, password = decoded.split(':', 1)
                        else:
                            method = decoded
                            password = ""
                    except:
                        userinfo_dec = unquote(userinfo)
                        if ':' in userinfo_dec:
                            method, password = userinfo_dec.split(':', 1)
                        else:
                            method = userinfo_dec
                            password = ""
                else:
                    logging.error(f"Invalid ss link format: {link}")
                    return None, None

            if port is None:
                logging.error(f"Missing port in ss link: {link}")
                return None, None

            bean["addr"] = host
            bean["port"] = port
            bean["sec"] = method
            bean["pass"] = password
            if plugin:
                bean["c_cfg"] = plugin

            stream = bean["stream"]
            stream["net"] = params.get("type", "tcp")
            stream["sec"] = params.get("security", "none")
            stream["sni"] = params.get("sni", host)
            stream["insecure"] = params.get("allowInsecure", "false") == "true"
            if stream["net"] == "tcp":
                stream["h_type"] = params.get("headerType", "")
            if stream["net"] == "grpc":
                stream["ed_name"] = params.get("serviceName", params.get("path", ""))
                stream["path"] = params.get("serviceName", params.get("path", ""))
            if stream["sec"] == "tls":
                stream["alpn"] = params.get("alpn", "")
                stream["utls"] = params.get("fp", "")

        else:
            return None, None

        return bean, protocol_type

    except Exception as e:
        logging.error(f"Error parsing link {link}: {e}")
        return None, None

# Основная функция для добавления профилей
def add_configs_to_nekoray(config_file_path, profiles_dir, group_file):
    # Проверяем существование директории профилей
    if not os.path.exists(profiles_dir):
        logging.info(f"Profiles directory does not exist, creating: {profiles_dir}")
        os.makedirs(profiles_dir, exist_ok=True)
    if not os.access(profiles_dir, os.W_OK):
        logging.error(f"No write permission for {profiles_dir}. Run 'chmod -R 755 {profiles_dir}'")
        sys.exit(1)

    # Проверяем существование файла конфигураций
    if not os.path.exists(config_file_path):
        logging.error(f"Config file not found: {config_file_path}")
        sys.exit(1)
    if not os.access(config_file_path, os.R_OK):
        logging.error(f"No read permission for {config_file_path}. Run 'chmod 644 {config_file_path}'")
        sys.exit(1)

    # Читаем ссылки из файла
    try:
        with open(config_file_path, 'r', encoding='utf-8') as f:
            links = [line.strip() for line in f if line.strip()]
        logging.info(f"Read {len(links)} links from {config_file_path}: {links[:5]}")
        if not links:
            logging.error(f"Config file {config_file_path} is empty")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading config file {config_file_path}: {e}")
        sys.exit(1)

    # Читаем текущий файл группы (0.json)
    try:
        if not os.path.exists(group_file):
            logging.info(f"Group file does not exist, creating: {group_file}")
            group_data = {
                "archive": False,
                "front_proxy_id": -1,
                "id": 0,
                "info": "",
                "landing_proxy_id": -1,
                "lastup": 0,
                "manually_column_width": False,
                "name": "Default",
                "order": [],
                "skip_auto_update": False,
                "url": ""
            }
        else:
            with open(group_file, 'r', encoding='utf-8') as f:
                group_data = json.load(f)
            logging.info(f"Read group file: {group_file}, current order: {group_data.get('order', [])}")
    except Exception as e:
        logging.error(f"Error reading group file {group_file}: {e}")
        sys.exit(1)

    # Получаем текущий максимальный ID профиля
    current_ids = group_data.get("order", [])
    next_id = max(current_ids, default=-1) + 1 if current_ids else 0
    logging.info(f"Starting profile ID: {next_id}")

    # Обрабатываем каждую ссылку
    for link in links:
        # Получаем host (IP или домен)
        host, _ = get_host_port(link)
        if not host:
            logging.warning(f"Skipping link without host: {link}")
            continue

        # Проверяем, является ли host IP-адресом
        if is_valid_ip(host):
            ip = host
        else:
            # Если host - домен, разрешаем в IP
            try:
                ip = socket.gethostbyname(host)
                logging.info(f"Resolved domain {host} to IP {ip}")
            except Exception as e:
                logging.warning(f"Could not resolve domain {host}: {e}. Skipping GeoIP lookup.")
                ip = None

        # Получаем страну по IP
        country_code = None
        if ip:
            country_code = get_country_from_ip(ip)
            time.sleep(1)  # Задержка 1 сек для уважения лимитов API

        # Генерируем имя профиля с флагом
        profile_name = "unnamed_profile"
        if link.startswith("vmess://"):
            try:
                json_str = base64.b64decode(link[8:] + '===').decode('utf-8')
                data = json.loads(json_str)
                profile_name = data.get("ps", "unnamed_profile").replace(" ", "_").replace("@", "").replace(":", "_")
            except Exception:
                pass
        elif link.startswith("vless://") or link.startswith("trojan://") or link.startswith("ss://"):
            profile_name = f"{link.split('://')[0]}_{uuid.uuid4().hex[:8]}"

        flag = country_to_flag(country_code) if country_code else ""
        profile_name = f"{flag}{country_code} {profile_name}"

        bean, protocol_type = get_nekoray_profile(link, profile_name)
        if bean is None:
            logging.warning(f"Skipping invalid link: {link}")
            continue

        # Создаём полный профиль
        profile = {
            "bean": bean,
            "dl": "",
            "gid": 0,
            "id": next_id,
            "report": "",
            "traffic": {"dl": 0, "ul": 0},
            "type": protocol_type,
            "ul": "",
            "yc": 0
        }

        # Формируем имя файла профиля с использованием ID
        profile_filename = os.path.join(profiles_dir, f"{next_id}.json")
        logging.info(f"Attempting to save profile: {profile_filename}")

        # Сохраняем профиль
        try:
            with open(profile_filename, 'w', encoding='utf-8') as f:
                json.dump(profile, f, indent=2, ensure_ascii=False)
            if os.path.exists(profile_filename):
                logging.info(f"Saved profile: {profile_filename}")
                # Добавляем ID профиля в order
                if next_id not in group_data["order"]:
                    group_data["order"].append(next_id)
                next_id += 1
            else:
                logging.error(f"Profile file {profile_filename} was not created")
        except Exception as e:
            logging.error(f"Error saving profile {profile_filename}: {e}")

    # Сохраняем обновлённый файл группы (0.json)
    try:
        with open(group_file, 'w', encoding='utf-8') as f:
            json.dump(group_data, f, indent=2, ensure_ascii=False)
        if os.path.exists(group_file):
            logging.info(f"Updated group file: {group_file}, new order: {group_data.get('order', [])}")
        else:
            logging.error(f"Group file {group_file} was not updated")
    except Exception as e:
        logging.error(f"Error saving group file {group_file}: {e}")

# Параметры
CONFIG_FILE_PATH = "results/fast_configs.txt"
PROFILES_DIR = "/Users/mr-js/Library/Preferences/nekoray/config/profiles"
GROUP_FILE = "/Users/mr-js/Library/Preferences/nekoray/config/groups/0.json"

# Запуск
if __name__ == "__main__":
    add_configs_to_nekoray(CONFIG_FILE_PATH, PROFILES_DIR, GROUP_FILE)