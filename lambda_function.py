import boto3
from botocore.exceptions import ClientError
import os
from pydantic import ValidationError
from utils import (
    create_response, not_valid_response, parse_event
)
from logger import logger

class InternalException(Exception):
    pass

CHALLENGE_NAME: str = "ChallengeName"
NEW_PWD_CHALLENGE: str = 'NEW_PASSWORD_REQUIRED'

REGION_NAME: str = os.getenv('AWS_REGION_NAME', 'eu-central-1')
CLIENT_ID: str = os.getenv('CALC_APP_CLIENT_ID', '')

client = boto3.client('cognito-idp', region_name=REGION_NAME)

def initiate_auth(client, username, password) -> dict:
    response = client.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=CLIENT_ID,
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": password
        }
    )
    return response

def new_pwd_challenge(client, username: str, password: str, session_id: str) -> dict:
    response: dict = client.respond_to_auth_challenge(
        ClientId=CLIENT_ID,
        ChallengeName=NEW_PWD_CHALLENGE,
        Session=session_id,
        ChallengeResponses = {
            "USERNAME": username,
            "NEW_PASSWORD": password
        }
    )
    return response

def login(event: dict) -> dict:
    try:
        username, password, new_password = parse_event(event)
        logger.debug(f'login. credentials: username={username}, password={password}, new_password={new_password}')
        response: dict = initiate_auth(client, username, password)
        logger.debug(f'login. first response={response}')
        challenge_name = response.get(CHALLENGE_NAME)
        if challenge_name:
            if not challenge_name == NEW_PWD_CHALLENGE:
                print(f"Unexpected ChallengeName {challenge_name}")
                raise InternalException("Unexpected challenge occurred")
            if new_password is None:
                raise ValidationError('New password is required for the first login')
            challenge_response = new_pwd_challenge(client, username, new_password, response.get("Session", ""))
            logger.debug(f'login. challenge response={challenge_response}')
            return challenge_response
        return response
    except ClientError as e:
        logger.exception(e.response.get("Error", "Unknown client error"))
        raise InternalException("Unknown client error") from e


def lambda_handler(event, context) -> dict:
    try:
        logger.debug(event)
        response = login(event)
        logger.debug(f'Login response: {response}')
        return create_response(200, {"response": response})
    except ValidationError as ve:
        logger.debug(f"ValidationError: {ve.errors(include_context=False,include_url=False,include_input=False)}")
        return not_valid_response(ve)
    except Exception as e:
        logger.debug(f"Error type={type(e)}, Response 500")
        return create_response(500, {"error": str(e)})
