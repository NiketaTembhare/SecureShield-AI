import logging
import json
import datetime
import sys
from typing import Any, Dict

class JsonFormatter(logging.Formatter):
    """
    Custom log formatter that outputs logs in JSON format.
    """
    def format(self, record):
        log_obj = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName
        }
        
        # Add any extra fields passed in the 'extra' dict
        if hasattr(record, "extra_fields"):
            log_obj.update(record.extra_fields)
            
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_obj)

def get_logger(name: str):
    logger = logging.getLogger(name)
    
    # If logger already has handlers, don't add more (avoid duplicates)
    if logger.handlers:
        return logger
        
    logger.setLevel(logging.INFO)
    
    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    
    return logger

# Convenience class for security events
class SecurityLogger:
    def __init__(self, name="secureshield.security"):
        self.logger = get_logger(name)

    def log_event(self, event_type: str, status: str, user_id: str, details: Dict[str, Any]):
        """
        Logs a structured security event.
        Example: log_event("pii_detection", "blocked", "user_123", {"field": "email"})
        """
        extra = {
            "event_type": event_type,
            "status": status,
            "user_id": user_id,
            "details": details
        }
        # Use the 'extra' parameter to pass custom fields to the formatter
        # We attach it to the record in a way the formatter can find it
        self.logger.info(f"Security event: {event_type}", extra={"extra_fields": extra})

# Singleton instances
logger = get_logger("secureshield")
security_logger = SecurityLogger()
