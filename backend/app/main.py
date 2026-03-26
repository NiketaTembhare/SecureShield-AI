from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.controllers import prompt_controller

app = FastAPI(title="SecureShield AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(prompt_controller.router)

@app.get("/api/health")
async def health_check():
    return {"status": "ok"}
