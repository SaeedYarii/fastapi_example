from typing import Optional

from app.base import CamelModel


class FizzSchema(CamelModel):
    """Fizz schema"""

    fizz_id: Optional[int] = None
    name: str
    purpose: str
