from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, Field
from datetime import datetime
from database import accounts_validators
from database.models.accounts import UserGroupEnum, GenderEnum


class UserBaseSchema(BaseModel):
    email: EmailStr = Field(min_length=2, max_length=120)
    is_active: bool = False
    group: UserGroupEnum


class UserReadSchema(UserBaseSchema):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserCreateSchema(UserBaseSchema):
    password: str = Field(min_length=8)


class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str


class UserProfileSchema(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    avatar: str | None = None
    gender: GenderEnum | None = None
    date_of_birth: datetime | None = None
    info: str | None = None

    model_config = ConfigDict(from_attributes=True)


class UserWithProfileSchema(UserReadSchema):
    profile: UserProfileSchema | None = None


class UserProfileUpdateSchema(BaseModel):
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    avatar: str | None = Field(default=None, max_length=200)
    gender: GenderEnum | None = Field(default=None)
    date_of_birth: datetime | None = Field(default=None)


class ActivationTokenSchema(BaseModel):
    token: str
    expires_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenPairSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
