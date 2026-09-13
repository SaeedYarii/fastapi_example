import os
import requests
from fastapi import Header, HTTPException

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181/v1/data/authz/allow")

def authorize(resource, method):
    async def check_access(x_role: str = Header(default="guest")):
        input_data = {
            "user": {
                "role": x_role
            },
            "method": method,
            "resource": resource
        }

        try:
            response = requests.post(
                OPA_URL,
                json={"input": input_data},
                timeout=5
            )
        except requests.RequestException:
            raise HTTPException(
                status_code=503,
                detail="Authorization service unavailable"
            )

        if response.status_code != 200:
            raise HTTPException(
                status_code=503,
                detail="Authorization service unavailable"
            )

        result = response.json().get("result", False)

        if not result:
            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )

        return True

    return check_access