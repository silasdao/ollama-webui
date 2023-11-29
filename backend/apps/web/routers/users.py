from fastapi import Response
from fastapi import Depends, FastAPI, HTTPException, status
from datetime import datetime, timedelta
from typing import List, Union, Optional

from fastapi import APIRouter
from pydantic import BaseModel
import time
import uuid

from apps.web.models.users import UserModel, UserRoleUpdateForm, Users

from utils.utils import (
    get_password_hash,
    bearer_scheme,
    create_token,
)
from constants import ERROR_MESSAGES

router = APIRouter()

############################
# GetUsers
############################


@router.get("/", response_model=List[UserModel])
async def get_users(skip: int = 0, limit: int = 50, cred=Depends(bearer_scheme)):
    token = cred.credentials
    if user := Users.get_user_by_token(token):
        if user.role == "admin":
            return Users.get_users(skip, limit)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )


############################
# UpdateUserRole
############################


@router.post("/update/role", response_model=Optional[UserModel])
async def update_user_role(form_data: UserRoleUpdateForm, cred=Depends(bearer_scheme)):
    token = cred.credentials
    if not (user := Users.get_user_by_token(token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    if user.id != form_data.id:
        return Users.update_user_role_by_id(form_data.id, form_data.role)
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.ACTION_PROHIBITED,
        )
