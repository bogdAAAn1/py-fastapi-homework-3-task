from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserSchema(BaseModel):
    email: EmailStr
    password: str

    class Config:
        from_attributes = True

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        return accounts_validators.validate_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserRegistrationRequestSchema(UserSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(UserSchema):
    pass


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(UserSchema):
    token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
