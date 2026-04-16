from dotenv import load_dotenv
load_dotenv()

import os
from flask import Flask
from flask_cors import CORS

from routes.auth_routes import auth_bp
from routes.chat_routes import chat_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    
    # Critical: Load environment variables into Flask config
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "dev-secret-change-me")
    app.config["JWT_ISSUER"] = os.getenv("JWT_ISSUER", "secureshield")
    app.config["JWT_EXPIRES_MINUTES"] = int(os.getenv("JWT_EXPIRES_MINUTES", "480"))

    # from extensions import limiter
    # limiter.init_app(app)

    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
    CORS(
        app,
        origins=[frontend_url, "http://127.0.0.1:5173", "http://localhost:5173"],
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "OPTIONS", "DELETE", "PUT"],
        supports_credentials=True
    )

    from routes.admin_routes import admin_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(chat_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "version": "v1.0.18-debug-port-fix",
            "db_target": os.getenv("MONGODB_URI", "default-27017")
        }

    return app


# Module-level app instance for gunicorn (production)
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    # Enable debug=True temporarily to find the silent 500 error
    app.run(host="0.0.0.0", port=port, debug=True)
