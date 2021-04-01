from flask import Blueprint, request, jsonify
from flask_restx import Resource, Api, fields
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

import ory_hydra_client
from ory_hydra_client.api import public_api
from ory_hydra_client.rest import ApiException
from ory_hydra_client.model.oauth2_token_response import Oauth2TokenResponse
from ory_hydra_client.model.generic_error import GenericError
from pprint import pprint

from src import db
from src import jwt
from src.api.models import User


auth_blueprint = Blueprint('auth', __name__)
api = Api(auth_blueprint)

# Connecting with hydra
configuration = ory_hydra_client.Configuration(host="https://hydra-admin.pehchaan.kpgov.tech")


# from requests import get, post
# resp = get('http://host.docker.internal:4445').text
# print(resp)

class Auth(Resource):

    def post(self):
        post_data = request.get_json()
        nic = post_data.get('nic', None)
        password = post_data.get('password', None)
        if nic is None or password is None:
            return {"msg": "Bad username or password"}, 401

        user = User.query.filter_by(nic=nic).first()
        if not user:
            api.abort(404, f"User with {nic} does not exist")

        if user.nic != nic or user.password != password:
            return {"msg": "Bad username or password"}, 401

        access_token = create_access_token(identity=nic)
        return {'access_token': access_token}, 200


class Login(Resource):

    def post(self):
        post_data = request.get_json()
        nic = post_data.get('nic', None)
        if nic is not None:
            nic = nic.replace('-', '')
        password = post_data.get('password', None)
        remember = post_data.get('remember', False)
        challenge = post_data.get('login_challenge', None)
        if nic is None or password is None or challenge is None:
            return {"msg": "Bad username or password or login_challenge"}, 401

        user = User.query.filter_by(nic=nic).first()
        if not user:
            api.abort(404, f"User with {nic} does not exist")

        if user.nic != nic or user.password != password:
            return {"msg": "Bad username or password"}, 401

        with ory_hydra_client.ApiClient(configuration) as api_client:
            hydra = ory_hydra_client.AdminApi(api_client)
            login_request = hydra.get_login_request(challenge)
        
        # Our subject is NIC!
        subject = nic
        body = ory_hydra_client.AcceptLoginRequest(
            subject=subject, remember=remember
        )
        response = hydra.accept_login_request(
            login_request.challenge, body=body
        )
        return {
            'redirect_to': response.redirect_to
        }, 200


class Consent(Resource):
    
    def get(self):
        return {
            'success': True
        }, 200


    def post(self):
        post_data = request.get_json()
        consent_challenge = post_data.get('consent_challenge', None)
        requested_scope = post_data.get('requested_scope', [])
        nic = post_data.get('nic', None)
        remember = post_data.get('remember', False)
        
        if consent_challenge is None:
            return {"msg": "Invalid request, missing challenge from hydra!"}, 401
        print(nic)
        user = User.query.filter_by(nic=nic).first()
        if user is None:
            return {"msg": "NIC not registered!"}, 404
        session = {
            "access_token": {},
            "id_token": {
                "sub": "248289761001",
                "name": user.name,
                "preferred_username": user.email,
                "email": user.email,
                "picture": "",
            },
        }
        
        with ory_hydra_client.ApiClient(configuration) as api_client:
            hydra = ory_hydra_client.AdminApi(api_client)
            consent_request = hydra.get_consent_request(consent_challenge)
            body = ory_hydra_client.AcceptConsentRequest(
                grant_scope=requested_scope,
                grant_access_token_audience=consent_request.requested_access_token_audience,
                session=session,
                remember=remember,
            )
            response = hydra.accept_consent_request(
                consent_request.challenge, body=body
            )
        return {
            'redirect_to': response.redirect_to
        }, 200


class ConsentSkip(Resource):

    def post(self):
        post_data = request.get_json()
        consent_challenge = post_data.get('consent_challenge', None)
        nic = post_data.get('nic', None)
        
        if consent_challenge is None:
            return {"msg": "Invalid request, missing challenge from hydra!"}, 401
        
        user = User.query.filter_by(nic=nic).first()
        if user is None:
            return {"msg": "NIC not registered!"}, 404
        
        session = {
            "access_token": {},
            "id_token": {
                "sub": "248289761001",
                "name": user.name,
                "preferred_username": user.email,
                "email": user.email,
                "picture": "",
            },
        }

        with ory_hydra_client.ApiClient(configuration) as api_client:
            hydra = ory_hydra_client.AdminApi(api_client)
            consent_request = hydra.get_consent_request(consent_challenge)

            if consent_request.skip:
                body = ory_hydra_client.AcceptConsentRequest(
                    grant_scope=consent_request.requested_scope,
                    grant_access_token_audience=consent_request.requested_access_token_audience,
                    session=session,
                )
                response = hydra.accept_consent_request(
                    consent_request.challenge, body=body
                )
                return {
                    'skip': True,
                    'redirect_to': response.redirect_to
                }, 200
        
        return {
            'skip': False
        }, 200


class Introspection(Resource):

    def get(self, token_str, scopes):
        
        # Check if token and scopes is send via headers
        headers = request.headers
        if headers.get('Token') is not None:
            token_str = headers.get('Token', '')
            scopes = headers.get('Scopes', 'na')
        
        with ory_hydra_client.ApiClient(configuration) as api_client:
            hydra = ory_hydra_client.AdminApi(api_client)
            try:
                if scopes.lower() == 'na':
                    resp = hydra.introspect_o_auth2_token(token_str)
                else:
                    resp = hydra.introspect_o_auth2_token(token_str, scope=scopes)
            except ory_hydra_client.ApiException as e:
                print("Exception when calling AdminApi->introspect_o_auth2_token: %s\n" % e)
        
        return {
            'active': resp.active
        }, 200


class RefreshToken(Resource):

    def post(self):
        post_data = request.get_json()
        
        with ory_hydra_client.ApiClient(configuration) as api_client:
            # Create an instance of the API class
            api_instance = public_api.PublicApi(api_client)
            grant_type = post_data.get('grant_type', '')
            code = post_data.get('code', '')
            refresh_token = post_data.get('refresh_token', '')
            redirect_uri = post_data.get('redirect_uri', '')
            client_id = post_data.get('client_id', '')


            # example passing only required values which don't have defaults set
            # and optional values
            try:
                # The OAuth 2.0 Token Endpoint
                api_response = api_instance.oauth2_token(grant_type, code=code, refresh_token=refresh_token, redirect_uri=redirect_uri, client_id=client_id)
                pprint(api_response)
            except ory_hydra_client.ApiException as e:
                print("Exception when calling PublicApi->oauth2_token: %s\n" % e)
        
        return {
            'success': False
        }, 200


api.add_resource(Auth, '/authenticate')
api.add_resource(Login, '/loginn')
api.add_resource(Consent, '/consentt')
api.add_resource(ConsentSkip, '/consent_skip')
api.add_resource(Introspection, '/introspection/<token_str>/<scopes>')
api.add_resource(RefreshToken, '/refresh_token')
