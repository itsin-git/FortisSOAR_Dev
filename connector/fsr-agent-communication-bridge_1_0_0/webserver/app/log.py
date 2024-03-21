""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import logging
import os
from pathlib import Path

from .config import config

logger_formatter = logging.Formatter('%(asctime)s %(levelname)s %(module)s: %(funcName)s(): %(lineno)d: %(message)s',
                                     datefmt='%Y-%m-%d,%H:%M:%S')

os.makedirs(Path(config['LOGGING']['path']).parent, exist_ok=True)


def _get_logger(name, log_file_name, formatter=None):
    logger = logging.getLogger(name)
    logger.setLevel(config['LOGGING']['level'])
    logger_handler = logging.FileHandler(log_file_name)
    logger_handler.setLevel(logging.DEBUG)

    if formatter is not None:
        logger_handler.setFormatter(formatter)
    else:
        logger_handler.setFormatter(logger_formatter)
    logger.addHandler(logger_handler)
    return logger


def get_logger(name):
    return _get_logger(name, config['LOGGING']['path'])
