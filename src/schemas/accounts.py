from pydantic import BaseModel, EmailStr, field_validator
from database import accounts_validators

class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_user_password(cls, value: str) -> str:
        accounts_validators.validate_password(value)
        return value

class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True

class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

class MessageResponseSchema(BaseModel):
    message: str

class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_reset_password(cls, value: str) -> str:
        accounts_validators.validate_password(value)
        return value

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
