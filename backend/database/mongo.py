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
    # serverSelectionTimeoutMS=3000 → fail fast instead of hanging for 30s
    _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
    # Ping to verify we can actually reach the server
    _client.admin.command("ping")
    _db = _client[db_name]
    return _db


def get_db_safe():
    """Returns (db, error_message). Never raises."""
    try:
        return get_db(), None
    except ServerSelectionTimeoutError:
        return None, "Cannot connect to MongoDB at localhost:27017. Please make sure MongoDB is running."
    except Exception as e:
        return None, f"Database error: {str(e)}"
