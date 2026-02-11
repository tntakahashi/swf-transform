#!/usr/bin/env python
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2025 - 2026

import logging
import time


def process_payload(payload):
    """
    Process the payload.

    Args:
        payload (dict): The input payload to be processed.

    Returns:
        status (int): Status code indicating success (0) or failure (non-zero).
        result (dict): The processed result.
        error (str): Error message if any.
    """
    logger = logging.getLogger("PayloadProcessor")
    logger.info(f"Processing payload: {payload}")

    # Get slice_processing_time from payload, default to 30 seconds
    slice_processing_time = payload.get("slice_processing_time", 30)
    
    try:
        slice_processing_time = float(slice_processing_time)
        if slice_processing_time < 0:
            logger.warning(f"Invalid slice_processing_time {slice_processing_time}, using default 30 seconds")
            slice_processing_time = 30
    except (ValueError, TypeError):
        logger.warning(f"Cannot convert slice_processing_time to float: {slice_processing_time}, using default 30 seconds")
        slice_processing_time = 30
    
    logger.info(f"Sleeping for {slice_processing_time} seconds to simulate processing")
    time.sleep(slice_processing_time)
    logger.info(f"Finished sleeping for {slice_processing_time} seconds")

    # Example processing: add a new key-value pair
    processed_payload = payload.copy()
    processed_payload["processed"] = True
    processed_payload["actual_processing_time"] = slice_processing_time
    
    # Return True as status to indicate success (Transformer expects a truthy status)
    return True, processed_payload, None
