import os
import re
import glob
import socket
import base64
import time
import json
from urllib.parse import urlparse
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import asyncio

class VPNProbe:
    def __init__(self):
        self.folder_path = None
        self.verbose = True
        self.lock = asyncio.Lock()

    def print_status(self, message):
        if self.verbose:
            timestamp = time.strftime("%H:%M:%S", time.localtime())
            print(f"[{timestamp}] {message}")

    async def select_folder(self):
        while True:
            folder = input("📁 Enter folder path with config files: ").strip()
            if not folder:
                folder = os.getcwd()
            if os.path.isdir(folder):
                self.folder_path = folder
                self.print_status(f"✅ Selected folder: {folder}")
                break
            self.print_status("❌ Invalid path. Try again.")

    async def run_scan(self):
        if not self.folder_path:
            self.print_status("❌ No folder selected")
            return

        configs = []
        file_pattern = os.path.join(self.folder_path, "*.txt")
        files = glob.glob(file_pattern)

        if not files:
            self.print_status("⚠️ No files found")
            return

        self.print_status(f"\n📄 Found {len(files)} files")
        
        file_progress = tqdm(files, desc="📂 Files", position=0)
        
        for file in file_progress:
            file_progress.set_description(f"📂 {os.path.basename(file)[:20]}...")
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                links = re.findall(r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+)', content)
                
                link_progress = tqdm(links, desc="🔗 Links", position=1, leave=False)
                with ThreadPoolExecutor() as executor:
                    for link in link_progress:
                        link_progress.set_description(f"🔗 {link[:30]}...")
                        result = await self.check_link(link)
                        if result:
                            configs.append(result)
                            self.print_status(f"✅ Valid config: {result['host']}:{result['latency']}ms")
                        else:
                            self.print_status(f"❌ Invalid config: {link[:60]}...")
                    link_progress.close()
        
        file_progress.close()
        await self.save_results(configs)
        self.print_status("\n✅ Scan completed")

    async def check_link(self, link):
        try:
            if link.startswith("vmess://"):
                host, port = self.get_vmess_host_port(link)
            elif link.startswith("vless://"):
                host, port = self.get_vless_host_port(link)
            elif link.startswith("trojan://"):
                host, port = self.get_trojan_host_port(link)
            elif link.startswith("ss://"):
                host, port = self.get_ss_host_port(link)
            else:
                return None

            if not host or not port:
                return None

            latency = await self.test_latency(host, port)
            if latency is None or latency > 800:
                return None

            return {
                'link': link,
                'latency': latency,
                'host': host
            }
        except Exception as e:
            self.print_status(f"⚠️ Error checking {link[:30]}...: {str(e)}")
            return None

    def get_vmess_host_port(self, link):
        try:
            json_str = base64.b64decode(link[8:] + '===').decode('utf-8')
            data = json.loads(re.findall(r'{.*}', json_str)[0])
            return data.get('add'), data.get('port')
        except:
            return None, None

    def get_vless_host_port(self, link):
        try:
            parsed = urlparse(link)
            return parsed.hostname, parsed.port
        except:
            return None, None

    def get_trojan_host_port(self, link):
        try:
            parsed = urlparse(link)
            return parsed.hostname, parsed.port
        except:
            return None, None

    def get_ss_host_port(self, link):
        try:
            parsed = urlparse(link)
            return parsed.hostname, parsed.port
        except:
            return None, None

    async def test_latency(self, host, port, timeout=3):
        try:
            start = time.time()
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return int((time.time() - start) * 1000)
        except Exception as e:
            self.print_status(f"⚠️ Connection failed: {host}:{port} ({str(e)})")
            return None

    async def save_results(self, configs):
        if not os.path.exists('results'):
            os.makedirs('results')

        if not configs:
            self.print_status("⚠️ No valid configs found")
            return

        configs.sort(key=lambda x: x['latency'])
        
        with open('results/all_configs.txt', 'w', encoding='utf-8') as f:
            for config in configs:
                f.write(config['link'] + '\n')

        fast_configs = [c for c in configs if c['latency'] < 200]
        if fast_configs:
            with open('results/fast_configs.txt', 'w', encoding='utf-8') as f:
                for config in fast_configs:
                    f.write(config['link'] + '\n')

        self.print_status(f"💾 Saved {len(configs)} configs ({len(fast_configs)} fast)")

async def main():
    print("\n🛰 VPN Probe")
    print("---------------------")
    
    prober = VPNProbe()
    await prober.select_folder()
    await prober.run_scan()
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    asyncio.run(main())