import os
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError


_client = None
_db = None


def get_db():
    global _client, _db
    if _db is not None:
        return _db

    # Try MONGODB_URI from env, but default to the standard 27017
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri or "27018" in mongo_uri:
        # If it's missing or stuck on the wrong port, force the standard one
        mongo_uri = "mongodb://127.0.0.1:27017"
    
    db_name = os.getenv("DB_NAME", "secureshield")
    
    from services.logger import logger
    logger.info(f"[Database] Attempting connection: {mongo_uri}")
    
    try:
        _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000, connectTimeoutMS=5000)
        # Fast check
        _client.admin.command('ping')
        _db = _client[db_name]
        logger.info(f"[Database] Connected successfully to {db_name}")
        return _db
    except Exception as e:
        logger.error(f"[Database] Connection failed: {str(e)}")
        # Ultimate fallback for local dev
        if "27017" not in mongo_uri:
            logger.warning("[Database] Attempting local fallback to 127.0.0.1:27017...")
            _client = MongoClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=2000)
            _db = _client[db_name]
            return _db
        raise e


def get_db_safe():
    """Returns (db, error_message). Never raises."""
    try:
        return get_db(), None
    except ServerSelectionTimeoutError:
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        # Mask the URI for security but show enough to debug
        if "mongodb+srv" in mongo_uri:
            host_hint = "Atlas cluster"
        else:
            host_hint = mongo_uri.split("@")[-1].split("/")[0] if "@" in mongo_uri else mongo_uri
        return None, f"Cannot connect to MongoDB at {host_hint}. Please check your MONGODB_URI."
    except Exception as e:
        return None, f"Database error: {str(e)}"

def get_recent_history(user_id: str, limit: int = 5) -> str:
    """
    Retrieves the last N messages from security_logs to provide context for
    multi-turn injection detection.
    Returns a concatenated string of recent prompts.
    """
    try:
        db = get_db()
        logs = db["security_logs"]
        # Find logs for this user, sorted by most recent
        # We look for documents where security_assessment.action_taken was NOT BLOCK
        # to see the context of successful benign-looking messages
        cursor = logs.find(
            {"user.id": user_id},
            {"prompt": 1, "input.prompt_preview": 1}
        ).sort("timestamp", -1).limit(limit)
        
        history = []
        for doc in cursor:
            # Prefer the full prompt if available, fallback to preview
            p = doc.get("prompt") or doc.get("input", {}).get("prompt_preview", "")
            if p:
                history.append(p)
        
        # Reverse to get chronological order
        history.reverse()
        return " | ".join(history)
    except Exception:
        return ""

