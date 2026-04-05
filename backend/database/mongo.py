import os
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError


_client = None
_db = None


def get_db():
    global _client, _db
    if _db is not None:
        return _db

    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.getenv("DB_NAME", "secureshield")
    # serverSelectionTimeoutMS=5000 → enough for Atlas cold start
    _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    # Ping to verify we can actually reach the server
    _client.admin.command("ping")
    _db = _client[db_name]
    return _db


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

