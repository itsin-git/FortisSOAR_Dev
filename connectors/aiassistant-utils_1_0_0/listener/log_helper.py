from os import path, makedirs
import logging
LOG_DIR_PATH = '/var/log/cyops/cyops-integrations/ai-assistant/'
LOG_FILE_PATH = path.join(LOG_DIR_PATH, 'ai-assistant.log')
makedirs(LOG_DIR_PATH, exist_ok=True)
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s : %(process)d : %(levelname)s : %(message)s')
handler = logging.FileHandler(LOG_FILE_PATH)
handler.setFormatter(formatter)
logger.addHandler(handler)
