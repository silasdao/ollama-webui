from fastapi.security import HTTPBasicCredentials, HTTPBearer
from pydantic import BaseModel
from typing import Union, Optional

from passlib.context import CryptContext
from datetime import datetime, timedelta
import requests
import jwt

import config

JWT_SECRET_KEY = config.WEBUI_JWT_SECRET_KEY
ALGORITHM = "HS256"

##############
# Auth Utils
##############

bearer_scheme = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return (
        pwd_context.verify(plain_password, hashed_password) if hashed_password else None
    )


def get_password_hash(password):
    return pwd_context.hash(password)


def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
        payload["exp"] = expire

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET_KEY, options={"verify_signature": False})
    except Exception as e:
        return None


def extract_token_from_auth_header(auth_header: str):
    return auth_header[len("Bearer ") :]


def verify_token(request):
    try:
        if bearer := request.headers["authorization"]:
            token = bearer[len("Bearer ") :]
            return jwt.decode(
                token, JWT_SECRET_KEY, options={"verify_signature": False}
            )
        else:
            return None
    except Exception as e:
        return None
