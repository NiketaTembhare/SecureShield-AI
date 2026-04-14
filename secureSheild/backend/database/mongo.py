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
    
    print(f"[Database] Attempting connection: {mongo_uri}")
    
    try:
        _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000, connectTimeoutMS=5000)
        # Fast check
        _client.admin.command('ping')
        _db = _client[db_name]
        print(f"[Database] Connected successfully to {db_name}")
        return _db
    except Exception as e:
        print(f"[Database] Connection failed: {str(e)}")
        # Ultimate fallback for local dev
        if "27017" not in mongo_uri:
            print("[Database] Attempting local fallback to 127.0.0.1:27017...")
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

