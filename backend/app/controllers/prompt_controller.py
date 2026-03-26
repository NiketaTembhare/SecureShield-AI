from fastapi import APIRouter
from app.models.prompt import PromptRequest, DetectionResult
from app.services.firewall_service import scan_prompt

router = APIRouter(prefix="/api/prompt", tags=["prompt"])

@router.post("", response_model=DetectionResult)
async def handle_prompt(request: PromptRequest):
    return await scan_prompt(request.message, request.user_id, request.department)
