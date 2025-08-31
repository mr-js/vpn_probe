import os
import tomllib
import asyncio
import glob
import re
import time
import aiohttp
import logging
import sys
from tqdm.asyncio import tqdm_asyncio
from utils import log_status, setup_logging, create_temp_config_file
from config_parser import get_v2ray_config_data, get_vmess_host_port, get_vless_host_port, get_trojan_host_port, get_ss_host_port
from test_connections import test_latency, ping_youtube

# Настройка логгера для записи в файл
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

class VPNProbe:
    def __init__(self):
        try:
            with open("app.toml", "rb") as f:
                settings = tomllib.load(f)
        except FileNotFoundError:
            settings = {}
        self.folder_path = settings.get('folder_path', None)
        self.verbose = settings.get('verbose', True)
        self.latency = settings.get('latency', 500)
        self.filter = settings.get('filter', [])
        self.protocols = settings.get('protocols', ["vmess", "vless", "trojan", "ss"])
        self.lock = asyncio.Lock()
        self.target_url = "https://www.youtube.com"
        self.session = None
        self.link_pattern = re.compile(r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+)')

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100, force_close=True))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def select_folder(self):
        while True:
            folder = input("📁 Enter folder path with config files: ").strip()
            if not folder:
                folder = os.getcwd()
            try:
                if os.path.isdir(folder):
                    self.folder_path = folder
                    if self.verbose:
                        print(f"✅ Selected folder: {folder}")
                    break
                if self.verbose:
                    print("❌ Invalid path. Try again.")
            except Exception as e:
                if self.verbose:
                    print(f"❌ Error checking path: {str(e)}")

    async def run_scan(self):
        if not self.folder_path:
            if self.verbose:
                print("❌ No folder selected")
            return
        configs = []
        file_pattern = os.path.join(self.folder_path, "*.txt")
        files = glob.glob(file_pattern)
        if not files:
            if self.verbose:
                print("⚠️ No files found")
            return
        if self.verbose:
            print(f"📄 Found {len(files)} files")

        async def process_file(file):
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                links = self.link_pattern.findall(content)
                file_configs = []
                for link in tqdm_asyncio(links, desc=os.path.basename(file), leave=False, file=sys.stdout, mininterval=0.1):
                    result = await self.check_link(link)
                    if result:
                        file_configs.append(result)
                return file_configs
            except Exception as e:
                logging.error(f"Error processing {os.path.basename(file)}: {str(e)}")
                return []

        tasks = [process_file(file) for file in files]
        results = []
        for task in tqdm_asyncio.as_completed(tasks, total=len(tasks), desc="📂 Files", file=sys.stdout, mininterval=0.1):
            result = await task
            if isinstance(result, list):
                results.extend(result)
        valid_configs = [config for config in results if isinstance(config, dict) and 'link' in config]
        if valid_configs:
            await self.save_results(valid_configs)
        else:
            if self.verbose:
                print("⚠️ No valid configs to save")
        if self.verbose:
            print("✅ Scan completed")

    async def check_link(self, link):
        try:
            if not any(link.startswith(f"{protocol}://") for protocol in self.protocols):
                return None

            if self.filter and any(filt in link for filt in self.filter):
                return None

            host, port = None, None
            if link.startswith("vmess://"):
                host, port = get_vmess_host_port(link)
            elif link.startswith("vless://"):
                host, port = get_vless_host_port(link)
            elif link.startswith("trojan://"):
                host, port = get_trojan_host_port(link)
            elif link.startswith("ss://"):
                host, port = get_ss_host_port(link)

            if not host or not port:
                return None

            config_data = get_v2ray_config_data(link)
            if not config_data:
                logging.error(f"Failed to generate config: {link[:60]}...")
                return None

            temp_file = create_temp_config_file(config_data)
            logging.info(f"Debug config saved for {link[:60]}... in {temp_file}")

            latency = await test_latency(link, config_data, self.session)
            if latency is None:
                logging.error(f"Connection test failed for {link[:60]}...")
                return None

            is_youtube_reachable = await ping_youtube(link, config_data, self.session, self.target_url)
            if not is_youtube_reachable:
                logging.error(f"YouTube not reachable for {link[:60]}...")
                return None

            return {
                'link': link,
                'latency': latency,
                'host': host
            }
        except Exception as e:
            logging.error(f"Error checking {link[:60]}...: {str(e)}")
            return None

    async def save_results(self, configs):
        try:
            if not os.path.exists('results'):
                os.makedirs('results')
            if not configs:
                return
            configs.sort(key=lambda x: x['latency'])
            with open('results/all_configs.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(config['link'] for config in configs) + '\n')
            fast_configs = [c for c in configs if c['latency'] <= self.latency]
            if fast_configs:
                with open('results/fast_configs.txt', 'w', encoding='utf-8') as f:
                    f.write('\n'.join(config['link'] for config in fast_configs) + '\n')
        except Exception as e:
            logging.error(f"Error saving results: {str(e)}")

async def main():
    async with VPNProbe() as prober:
        if prober.folder_path is None:
            await prober.select_folder()
        await prober.run_scan()

if __name__ == "__main__":
    asyncio.run(main())
