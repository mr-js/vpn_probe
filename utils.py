import logging
import os
import tempfile
import json
import time
from tqdm.asyncio import tqdm_asyncio

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')

async def log_status(message, color="white"):
    colors = {
        "red": "\033[91m",
        "yellow": "\033[93m",
        "green": "\033[92m",
        "white": "\033[0m"
    }
    color_code = colors.get(color, colors["white"])
    print(f"{color_code}{message}\033[0m")

def create_temp_config_file(config_data, temp_dir='./.temp/'):
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', dir=temp_dir) as tf:
        json.dump(config_data, tf, indent=2)
        return tf.name
