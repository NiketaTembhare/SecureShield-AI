from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    email: str
    password_hash: str
    department: str
    role: str
    _id: Optional[str] = None

