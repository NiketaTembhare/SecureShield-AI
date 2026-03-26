from motor.motor_asyncio import AsyncIOMotorClient
from app.config.settings import MONGODB_URI, DB_NAME

client = AsyncIOMotorClient(MONGODB_URI)
db = client[DB_NAME]

async def get_db():
    return db
