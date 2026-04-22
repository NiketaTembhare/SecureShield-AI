from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "SecureShield V2"
    OPENROUTER_API_KEY: str 
    MONGODB_URI: str = "mongodb://localhost:27017" # Default to local, override in .env
    ENVIRONMENT: str = "development"


    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
