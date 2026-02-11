#!/usr/bin/env python
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2026

import logging
import os
import sys
import time


def setup_logging(name, stream=None, log_file=None, loglevel=None):
    """
    Setup logging
    """
    if loglevel is None:
        loglevel = logging.INFO

        if os.environ.get("PROMPT_LOG_LEVEL", None):
            prompt_log_level = os.environ.get("PROMPT_LOG_LEVEL", None)
            prompt_log_level = prompt_log_level.upper()
            if prompt_log_level in ["DEBUG", "CRITICAL", "ERROR", "WARNING", "INFO"]:
                loglevel = getattr(logging, prompt_log_level)
    if type(loglevel) in [str]:
        loglevel = loglevel.upper()
        loglevel = getattr(logging, loglevel)

    if log_file is not None:
        logging.basicConfig(
            filename=log_file,
            level=loglevel,
            format="%(asctime)s\t%(threadName)s\t%(name)s\t%(levelname)s\t%(message)s",
        )
    elif stream is None:
        if os.environ.get("PROMPT_LOG_FILE", None):
            prompt_log_file = os.environ.get("PROMPT_LOG_FILE", None)
            logging.basicConfig(
                filename=prompt_log_file,
                level=loglevel,
                format="%(asctime)s\t%(threadName)s\t%(name)s\t%(levelname)s\t%(message)s",
            )
        else:
            logging.basicConfig(
                stream=sys.stdout,
                level=loglevel,
                format="%(asctime)s\t%(threadName)s\t%(name)s\t%(levelname)s\t%(message)s",
            )
    else:
        logging.basicConfig(
            stream=stream,
            level=loglevel,
            format="%(asctime)s\t%(threadName)s\t%(name)s\t%(levelname)s\t%(message)s",
        )
    logging.Formatter.converter = time.gmtime
