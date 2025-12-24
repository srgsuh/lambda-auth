import json
from pydantic import BaseModel, field_validator, ValidationError

SPECIAL_CHARS = set(r'^$*.[\]{}()?-"!@#%&/\,><\':;|_~`+=')

def validate_password(value: str) -> None:
    if len(value) < 8:
        raise ValueError("Password must be at least 8 characters long")

    if not any(c.isdigit() for c in value):
        raise ValueError("Password must contain at least one digit")

    if not any(c.islower() for c in value):
        raise ValueError("Password must contain at least one lowercase letter")

    if not any(c.isupper() for c in value):
        raise ValueError("Password must contain at least one uppercase letter")

    has_special = any(c in SPECIAL_CHARS for c in value)
    has_inner_space = " " in value[1:-1]

    if not (has_special or has_inner_space):
        raise ValueError(
            "Password must contain a special character or a non-leading, non-trailing space"
        )

class LoginRequest(BaseModel):
    username: str
    password: str
    new_password: str | None = None

    @field_validator("new_password")
    @classmethod
    def is_none_or_valid(cls, value: str | None) -> str | None:
        if value is None:
            return value

        validate_password(value)
        return value

def parse_event(event: dict) -> LoginRequest:
    try:
        body: dict = json.loads(event["body"])
    except:
        raise ValidationError("Wrong message format")
    else:
        return LoginRequest(**body)

def create_response(status_code: int, payload: dict | str) -> dict:
    return {'statusCode': status_code, 'body': json.dumps(payload)}

def not_valid_response(ve: ValidationError) -> dict:
    return create_response(400, {
        "error": ve.errors(include_context=False,include_url=False,include_input=False)
        })
