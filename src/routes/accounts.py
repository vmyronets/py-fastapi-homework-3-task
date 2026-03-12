from datetime import datetime, timezone, timedelta
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
from schemas.accounts import (
    UserLoginSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    MessageResponseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: Session = Depends(get_db)
):
    try:
        # Check if email exists
        stmt = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(stmt)
        if result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        # Get default user group
        group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_stmt)
        user_group = group_result.scalars().first()
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found."
            )

        # Create user
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id)
        )
        db.add(new_user)
        await db.flush()

        # Create activation token
        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        return new_user
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_account(
        activation_data: UserActivationRequestSchema,
        db: Session = Depends(get_db)
):
    # Find user
    stmt = select(UserModel).where(UserModel.email == activation_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

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

    # Find token
    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == activation_data.token
    )
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    # Check expiration (SQLite timezone handling)
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    # Activate user
    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: Session = Depends(get_db)
):
    # Success message (always returned)
    success_message = {"message": "If you are registered, you will receive an email with instructions."}

    # Find active user
    stmt = select(UserModel).where(UserModel.email == reset_data.email, UserModel.is_active == True)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user:
        # Invalidate existing tokens
        stmt_del = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        await db.execute(stmt_del)

        # Create new token
        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        await db.commit()

    return success_message


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_password_complete(
        reset_data: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db)
):
    try:
        # Find user
        stmt = select(UserModel).where(UserModel.email == reset_data.email, UserModel.is_active == True)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Find token
        stmt_token = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        result_token = await db.execute(stmt_token)
        token_record = result_token.scalars().first()

        if not token_record or token_record.token != reset_data.token:
            if token_record:
                await db.delete(token_record)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Check expiration
        expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Reset password
        user.password = reset_data.password
        await db.delete(token_record)
        await db.commit()

        return {"message": "Password reset successfully."}
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    try:
        # Authenticate user
        stmt = select(UserModel).where(UserModel.email == login_data.email)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user or not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        # Check activation
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        # Generate tokens
        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        refresh_token_str = jwt_manager.create_refresh_token(data={"user_id": user.id})

        # Store refresh token
        new_refresh_token = RefreshTokenModel(
            user_id=cast(int, user.id),
            token=refresh_token_str,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.LOGIN_TIME_DAYS)
        )
        db.add(new_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer"
        }
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        refresh_data: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        # Decode and validate refresh token structure
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token payload."
        )

    # Check refresh token existence in DB
    stmt_token = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_data.refresh_token)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    # Check if user exists
    stmt_user = select(UserModel).where(UserModel.id == int(user_id))
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    # Generate new access token
    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    return {"access_token": new_access_token}
