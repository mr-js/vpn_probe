import asyncio
import subprocess
import os
import time
import logging
from utils import create_temp_config_file

async def test_latency(link, config_data, session, timeout=5):
    temp_file = None
    process = None
    try:
        temp_file = create_temp_config_file(config_data)

        process = await asyncio.create_subprocess_exec(
            'xray', 'run', '-c', temp_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        await asyncio.sleep(2)
        if process.returncode is not None:
            stderr = await process.stderr.read()
            logging.error(f"Xray process failed with error for {link[:60]}: {stderr.decode()}")
            return None

        start_time = time.perf_counter()
        async with session.get(
            'http://cp.cloudflare.com/generate_204',
            proxy='http://127.0.0.1:1080',
            timeout=timeout
        ) as response:
            end_time = time.perf_counter()
            if response.status == 204:
                return int((end_time - start_time) * 1000)
            logging.error(f"Connection test failed for {link[:60]} (HTTP {response.status})")
            return None
    except Exception as e:
        logging.error(f"Error during Xray test for {link[:60]}: {str(e)}")
        return None
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await process.wait()
            except Exception:
                pass
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)

async def ping_youtube(link, config_data, session, target_url, timeout=5):
    temp_file = None
    process = None
    try:
        temp_file = create_temp_config_file(config_data)

        process = await asyncio.create_subprocess_exec(
            'xray', 'run', '-c', temp_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        await asyncio.sleep(2)
        if process.returncode is not None:
            stderr = await process.stderr.read()
            logging.error(f"Xray process failed with error for {link[:60]}: {stderr.decode()}")
            return False

        async with session.get(
            target_url,
            proxy='http://127.0.0.1:1080',
            timeout=timeout
        ) as response:
            if response.status == 200:
                return True
            logging.error(f"YouTube not reachable for {link[:60]} (HTTP {response.status})")
            return False
    except Exception as e:
        logging.error(f"Error during YouTube ping for {link[:60]}: {str(e)}")
        return False
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await process.wait()
            except Exception:
                pass
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)
