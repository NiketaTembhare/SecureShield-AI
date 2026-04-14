import os
from dotenv import load_dotenv

# 1. Check BEFORE loading .env
print(f"DEBUG: MONGODB_URI (before load_dotenv): {os.getenv('MONGODB_URI', 'NOT SET')}")

# 2. Check AFTER loading .env
load_dotenv()
print(f"DEBUG: MONGODB_URI (after load_dotenv): {os.getenv('MONGODB_URI', 'NOT SET')}")

# 3. Check for specific port issues
uri = os.getenv("MONGODB_URI", "")
if "27018" in uri:
    print("WARNING: FOUND 27018 IN THE ENVIRONMENT!")
else:
    print("SUCCESS: 27018 NOT FOUND IN THE ACTIVE ENVIRONMENT.")
