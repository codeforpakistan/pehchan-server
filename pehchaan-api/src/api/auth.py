from flask import Blueprint, request, jsonify
from flask_restx import Resource, Api, fields
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

import ory_hydra_client
from ory_hydra_client.rest import ApiException

from src import db
from src import jwt
from src.api.models import User


auth_blueprint = Blueprint('auth', __name__)
api = Api(auth_blueprint)

# Connecting with hydra
configuration = ory_hydra_client.Configuration(host="http://host.docker.internal:4445")


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
        remember = post_data.get('remember', False)
        
        if consent_challenge is None:
            return {"msg": "Invalid request, missing challenge from hydra!"}, 401

        user = User.query.filter_by(nic='1730187464751').first()
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


api.add_resource(Auth, '/authenticate')
api.add_resource(Login, '/loginn')
api.add_resource(Consent, '/consentt')
