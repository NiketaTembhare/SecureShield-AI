from pydantic import BaseModel
from typing import Optional

class PromptRequest(BaseModel):
    message: str
    user_id: Optional[str] = "unknown"
    department: Optional[str] = "unknown"

class DetectionResult(BaseModel):
    is_blocked: bool
    reason: Optional[str] = None
    response: Optional[str] = None
