import asyncio
import json
import logging
import sys
from logging.handlers import RotatingFileHandler
 
import nats
from pymisp import MISPEvent, PyMISP
from settings import (
    LOG_FILE,
    MISP_API_KEY,
    MISP_API_URL,
    MISP_CERTIFICATE_VERIFY,
    MISP_ECS_ATTRIBUTES_MAP,
    NATS_URL,
    SUBSCRIBE_QUEUE,
    SUBSCRIBE_SUBJECT,
    log_format,
)
from utils.utils import extract_values_from_sequence
 
"""
Push events to MISP using its API
"""
 
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("misp_client")
log_file_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=100_000_000, backupCount=5
)
log_file_handler.setFormatter(log_format)
if logger.hasHandlers():
    logger.handlers.clear()
logger.addHandler(log_file_handler)
 
 
def push_to_misp(read_message) -> bool or dict:
    try:
        info = (
            ((read_message.get("threat", {}) or {}).get(
                "enrichments", {}) or {}).get(
                "indicator", {}
            )
            or {}
        ).get("reference") or "Other"
        event_obj = MISPEvent()
        event_obj.info = info
        for ecs_attribute, value in extract_values_from_sequence(read_message):
            try:
                misp_attribute = MISP_ECS_ATTRIBUTES_MAP.get(
                    ecs_attribute, "other"
                )
                event_obj.add_attribute(
                    misp_attribute,
                    value if misp_attribute != "other"
                    else f"{ecs_attribute}: {value}",
                )
            except ValueError as e:
                logger.warning(
                    f"Can't add attribute {ecs_attribute}={value}: {e}"
                )
        event = misp.add_event(event_obj, pythonify=True)
        logger.info(f"event: {event}")
    except AttributeError as e:
        tb = sys.exception().__traceback__
        logger.error(e.with_traceback(tb))
        return False
    if not event:
        return False
    event_id = event.get("id")
    if not event_id:
        return False
    return True
 
 
async def receive_enriched_events():
    import socket
 
    nc = await nats.connect(NATS_URL, name=socket.gethostname() + "[SUB]")
    enriched_events = await nc.subscribe(
        SUBSCRIBE_SUBJECT, queue=SUBSCRIBE_QUEUE
    )
    try:
        async for msg in enriched_events.messages:
            logger.info(f"new message from {SUBSCRIBE_QUEUE} queue: {msg}")
            read_message = json.loads(msg.data.decode())
            ioc = (read_message.get("source", {}) or {}).get("ip")
            if not ioc:
                ioc = (read_message.get("source", {}) or {}).get("domain")
            if not ioc:
                ioc = (read_message.get("source", {}) or {}).get("url")
            if ioc:
                pushed_to_misp = push_to_misp(read_message)
                if pushed_to_misp:
                    logger.info(
                        f"Pushed successfully to MISP: {read_message}"
                    )
    except Exception as e:
        await nc.close()
        tb = sys.exception().__traceback__
        logger.error(e.with_traceback(tb))
 
 
async def receive_normalized_events():
    import socket
    nc = await nats.connect(NATS_URL, name=socket.gethostname() + "[SUB]")
    normalized_events = await nc.subscribe(SUBSCRIBE_SUBJECT, queue=SUBSCRIBE_QUEUE)
 
    try:
        async for msg in normalized_events.messages:
            # 1. Load outer JSON
            outer_data = json.loads(msg.data.decode())
 
            # 2. Load inner JSON (content of "message")
            inner_message = json.loads(outer_data.get("message", "{}"))
 
            # 3. Search for IP in the real message
            # In your log, the IP is at the end of the internal "message" field: ",,,,,223.247.154.13"
            raw_msg_content = inner_message.get("message", "")
            ioc = None
 
            # Simple logic to extract IP if it comes after the commas
            if "," in raw_msg_content:
                ioc = raw_msg_content.split(",")[-1].strip()
 
            if ioc:
                # Trigger MISP
                pushed_to_misp = await loop.run_in_executor(None, push_to_misp, inner_message)
                if pushed_to_misp:
                    logger.info(f"Pushed successfully to MISP: {ioc}")
    except Exception as e:
        await nc.close()
        tb = sys.exception().__traceback__
        logger.error(e.with_traceback(tb))
 
 
async def main():
    if SUBSCRIBE_SUBJECT == "normalized_events":
        logger.info("Mode: Normalized Events")
        t1 = loop.create_task(receive_normalized_events())
    else:
        logger.info("Mode: Enriched Events")
        t1 = loop.create_task(receive_enriched_events())
    await asyncio.wait(
        [
            t1,
        ]
    )
    return ("task 1", t1)
 
 
if __name__ == "__main__":
    logger.info("starting MISP Client")
    misp = PyMISP(MISP_API_URL, MISP_API_KEY, MISP_CERTIFICATE_VERIFY)
    loop = asyncio.get_event_loop()
    loop.set_debug(1)
    t1 = loop.run_until_complete(main())
    loop.close()