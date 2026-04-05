import os
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from routes.auth_routes import auth_bp
from routes.chat_routes import chat_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "dev-secret-change-me")
    app.config["JWT_ISSUER"] = os.getenv("JWT_ISSUER", "secureshield")
    app.config["JWT_EXPIRES_MINUTES"] = int(os.getenv("JWT_EXPIRES_MINUTES", "480"))

    from extensions import limiter
    limiter.init_app(app)

    CORS(
        app,
        origins="*",
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "OPTIONS", "DELETE", "PUT"],
    )

    from routes.admin_routes import admin_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(chat_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/health/db")
    def health_db():
        mongo_uri = os.getenv("MONGODB_URI", "NOT_SET")
        uri_type = "atlas" if "mongodb+srv" in mongo_uri else "local" if mongo_uri != "NOT_SET" else "NOT_SET"
        from database.mongo import get_db_safe
        db, err = get_db_safe()
        return {
            "uri_configured": mongo_uri != "NOT_SET",
            "uri_type": uri_type,
            "connected": db is not None,
            "error": err
        }

    return app


# Module-level app instance for gunicorn (production)
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "1") == "1")
