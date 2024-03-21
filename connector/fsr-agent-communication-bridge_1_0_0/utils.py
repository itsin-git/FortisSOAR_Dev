import configparser
import os
from pathlib import Path

root_directory = Path(__file__).parent.resolve()
config_file_path = os.path.join(root_directory, 'webserver', 'config', 'config.ini')
config = configparser.ConfigParser()
config.read(config_file_path)
