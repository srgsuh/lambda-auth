import boto3
from botocore.exceptions import ClientError
import os
from pydantic import ValidationError
from utils import (
    LoginRequest, create_response, not_valid_response, parse_event
)
from logger import logger

class InternalException(Exception):
    pass

def getenv(param_id: str, default_value: str | None = None) -> str:
    value = os.getenv(param_id, default_value)
    if value is None:
        raise InternalException(f"Configuration error. Missing parameter \"{param_id}\"")
    return value

CHALLENGE_NAME: str = "ChallengeName"
NEW_PWD_CHALLENGE: str = 'NEW_PASSWORD_REQUIRED'
AUTH_RESULT: str = "AuthenticationResult"

client = boto3.client('cognito-idp', region_name=getenv('AWS_REGION_NAME', 'eu-central-1'))

def initiate_auth(client, request: LoginRequest) -> dict:
    response = client.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=getenv('CALC_APP_CLIENT_ID'),
        AuthParameters={
            "USERNAME": request.username,
            "PASSWORD": request.password
        }
    )
    return response

def process_challenge(client, challenge: dict, request: LoginRequest) -> dict:
    challenge_name = challenge.get(CHALLENGE_NAME)

    if not challenge_name == NEW_PWD_CHALLENGE:
            logger.debug(f"process_challenge. Unexpected ChallengeName {challenge_name}")
            raise InternalException(f"Unexpected challenge {challenge_name} occurred")
    if request.new_password is None:
        logger.debug(f'process_challenge. Missing new password')
        raise ValidationError('New password is required for the first login')
    
    response: dict = client.respond_to_auth_challenge(
        ClientId=getenv('CALC_APP_CLIENT_ID'),
        ChallengeName=NEW_PWD_CHALLENGE,
        Session=challenge.get("Session", ""),
        ChallengeResponses = {
            "USERNAME": request.username,
            "NEW_PASSWORD": request.new_password
        }
    )
    logger.debug(f'process_challenge. challenge response={response}')
    return response

def login(event: dict) -> dict:
    try:
        request: LoginRequest = parse_event(event)
        logger.debug(f'login. request={request}')
        response: dict = initiate_auth(client, request)
        logger.debug(f'login. first response={response}')
        if CHALLENGE_NAME in response:
            response = process_challenge(client, response, request)
        
        return response
    except ClientError as e:
        logger.exception(e.response.get("Error", "Unknown client error"))
        raise

def lambda_handler(event, context) -> dict:
    try:
        logger.debug(event)
        login_response = login(event)
        logger.debug(f'Login response: {login_response}')
        reply = login_response.get(AUTH_RESULT, {})
        return create_response(200, reply)
    except ValidationError as ve:
        logger.debug(f"ValidationError: {ve.errors(include_context=False,include_url=False,include_input=False)}")
        return not_valid_response(ve)
    except Exception as e:
        logger.debug(f"Error type={type(e)}, Response 500")
        return create_response(500, {"error": str(e)})
