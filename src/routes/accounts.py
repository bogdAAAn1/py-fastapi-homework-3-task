from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from schemas.accounts import UserSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="Register new user",
    status_code=status.HTTP_201_CREATED
)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    check_user = user.scalars().first()
    if check_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    user = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    check_user_group = user.scalars().first()
    if not check_user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found."
        )

    try:
        create_user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=check_user_group.id
        )
        db.add(create_user)
        await db.flush()

        activate_token = ActivationTokenModel(user_id=create_user.id)
        db.add(activate_token)
        await db.commit()
        await db.refresh(create_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    else:
        return UserRegistrationResponseSchema.model_validate(create_user)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate new user",
    status_code=status.HTTP_200_OK
)
async def activate(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await db.execute(
        select(ActivationTokenModel)
        .options(
            joinedload(ActivationTokenModel.user)
        ).join(UserModel).where(
            UserModel.email == user_data.email,
            ActivationTokenModel.token == user_data.token
        )
    )
    activate_user = user.scalars().first()
    current_time = datetime.now(timezone.utc)
    if activate_user:
        expires_at_utc = cast(datetime, activate_user.expires_at).replace(tzinfo=timezone.utc)
        if expires_at_utc < current_time:
            await db.delete(activate_user)
            await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token."
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = activate_user.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(activate_user)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Reset password request",
    status_code=status.HTTP_200_OK
)
async def password_reset(
        user_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = await db.execute(
        select(UserModel).filter_by(email=user_data.email)
    )
    user = stmt.scalars().first()
    if not user or not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Reset password complete",
    status_code=status.HTTP_200_OK
)
async def password_reset_complete(
        user_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = await db.execute(select(UserModel).filter_by(email=user_data.email))
    user = stmt.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    stmt = await db.execute(select(PasswordResetTokenModel).filter_by(user_id=user.id))
    user_token = stmt.scalars().first()

    if not user_token or user_token.token != user_data.token:
        if user_token:
            await db.delete(user_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, user_token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(user_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = user_data.password
        await db.delete(user_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="Login user",
    status_code=status.HTTP_201_CREATED
)
async def login_user(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    stmt = await db.execute(
        select(UserModel).filter_by(email=user_data.email)
    )
    user = stmt.scalars().first()
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token
        )
        db.add(refresh_token)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh user token",
    status_code=status.HTTP_200_OK
)
async def refresh_token(
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decode_token = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = decode_token.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    stmt = await db.execute(
        select(RefreshTokenModel).filter_by(token=token_data.refresh_token)
    )
    new_refresh_token = stmt.scalars().first()
    if not new_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    stmt = await db.execute(
        select(UserModel).filter_by(id=user_id)
    )
    user = stmt.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    new_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=new_access_token)
