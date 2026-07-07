import secrets
import inspect
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)

router = APIRouter()


def _safe_create_token(method, user_id):
    try:
        sig = inspect.signature(method)
        param_names = list(sig.parameters.keys())
    except Exception:
        param_names = []

    param_names = [p for p in param_names if p not in ("self", "cls")]

    if "data" in param_names:
        return method(data={"user_id": user_id})
    if "payload" in param_names:
        return method(payload={"user_id": user_id})
    if "subject" in param_names:
        return method(subject=user_id)
    if "sub" in param_names:
        return method(sub=user_id)

    try:
        return method({"user_id": user_id})
    except Exception:
        try:
            return method(user_id)
        except Exception:
            try:
                return method(data={"user_id": user_id})
            except Exception:
                return method(payload={"user_id": user_id})


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    password = user_data.password
    if len(password) < 8:
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least 8 characters."
        )
    if not any(c.isupper() for c in password):
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least one uppercase letter."
        )
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least one digit."
        )
    if not any(c.islower() for c in password):
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least one lower letter."
        )
    special_chars = "@$!%*?#&"
    if not any(c in special_chars for c in password):
        raise HTTPException(
            status_code=422,
            detail=(
                "Password must contain at least one special character: "
                "@, $, !, %, *, ?, #, &."
            )
        )

    try:
        query = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(query)
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"A user with this email {user_data.email} "
                    "already exists."
                )
            )

        group_query = select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
        group_result = await db.execute(group_query)
        default_group = group_result.scalar_one_or_none()
        group_id = default_group.id if default_group else 1

        hashed_pwd = hash_password(user_data.password)
        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed_pwd,
            is_active=False,
            group_id=group_id
        )
        db.add(new_user)
        await db.flush()

        act_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        activation_record = ActivationTokenModel(
            token=act_token,
            user_id=cast(int, new_user.id),
            expires_at=expires_at
        )
        db.add(activation_record)
        await db.commit()

        return new_user

    except HTTPException as http_ex:
        await db.rollback()
        raise http_ex
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate_account(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user_query = select(UserModel).where(UserModel.email == data.email)
    user_res = await db.execute(user_query)
    user = user_res.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_query = select(ActivationTokenModel).where(
        ActivationTokenModel.token == data.token,
        ActivationTokenModel.user_id == user.id
    )
    token_res = await db.execute(token_query)
    token_record = token_res.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(
        tzinfo=timezone.utc
    )
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    success_msg = {
        "message": (
            "If you are registered, you will "
            "receive an email with instructions."
        )
    }

    user_query = select(UserModel).where(UserModel.email == data.email)
    user_res = await db.execute(user_query)
    user = user_res.scalar_one_or_none()

    if not user or not user.is_active:
        return success_msg

    delete_query = delete(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    await db.execute(delete_query)

    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    new_reset_record = PasswordResetTokenModel(
        token=reset_token,
        user_id=cast(int, user.id),
        expires_at=expires_at
    )
    db.add(new_reset_record)
    await db.commit()

    return success_msg


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user_query = select(UserModel).where(UserModel.email == data.email)
    user_res = await db.execute(user_query)
    user = user_res.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_query = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.token == data.token,
        PasswordResetTokenModel.user_id == user.id
    )
    token_res = await db.execute(token_query)
    token_record = token_res.scalar_one_or_none()

    if not token_record:
        delete_query = delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        await db.execute(delete_query)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(
        tzinfo=timezone.utc
    )
    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user._hashed_password = hash_password(data.password)
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_200_OK
)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    user_query = select(UserModel).where(UserModel.email == data.email)
    user_res = await db.execute(user_query)
    user = user_res.scalar_one_or_none()

    if not user or not verify_password(
        data.password, user._hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = _safe_create_token(
            jwt_manager.create_access_token, user.id
        )
        refresh_token = _safe_create_token(
            jwt_manager.create_refresh_token, user.id
        )

        days_to_expire = getattr(settings, "LOGIN_TIME_DAYS", 7)
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=days_to_expire
        )

        if hasattr(RefreshTokenModel, "create"):
            token_instance = RefreshTokenModel.create(
                token=refresh_token,
                user_id=cast(int, user.id),
                expires_at=expires_at
            )
            db.add(token_instance)
            await db.commit()
        else:
            refresh_record = RefreshTokenModel(
                token=refresh_token,
                user_id=cast(int, user.id),
                expires_at=expires_at
            )
            db.add(refresh_record)
            await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
@router.post(
    "/api/v1/accounts/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_payload = jwt_manager.decode_refresh_token(
            data.refresh_token
        )
        user_id = decoded_payload.get("user_id")
    except (BaseSecurityError, Exception):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    token_query = select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token
    )
    token_res = await db.execute(token_query)
    token_record = token_res.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_query = select(UserModel).where(UserModel.id == user_id)
    user_res = await db.execute(user_query)
    user = user_res.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if token_record.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    new_access_token = _safe_create_token(
        jwt_manager.create_access_token, user.id
    )

    return {"access_token": new_access_token}
