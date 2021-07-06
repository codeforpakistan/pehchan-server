import os
from pprint import pprint
from requests import get, post
from flask import Blueprint, request, jsonify
from flask_restx import Resource, Api, fields, Namespace
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

import ory_hydra_client
from ory_hydra_client.rest import ApiException
from ory_hydra_client.api import public_api

from src import db
from src import jwt
from src.api.models import User

# Paigham URL
paigham_url = os.getenv('PAIGHAM_URL')
paigham_key = os.getenv('PAIGHAM_KEY', '')


users_namespace = Namespace("users")  # new

users_blueprint = Blueprint('users', __name__)
api = Api(users_blueprint)


# Connecting with hydra
configuration = ory_hydra_client.Configuration(host="https://hydra-admin.pehchaan.kpgov.tech")


user = api.model('User', {
    'id': fields.Integer(readOnly=True),
    'nic': fields.String(required=True),
    'name': fields.String(required=True),
    'phone': fields.String(required=True),
    'email': fields.String(required=True),
    'created_date': fields.DateTime,
    'modified_date': fields.DateTime
})


class Users(Resource):

    @api.marshal_with(user)
    def get(self, id_type,user_id):
        if id_type == 'id':
            user = User.query.filter_by(id=int(user_id)).first()
        elif id_type == 'nic':
            user = User.query.filter_by(nic=user_id).first()
        else:
            api.abort(400, f"Invalid request")

        if not user:
            api.abort(404, f"User {user_id} does not exist")
        return user, 200

    def delete(self, id_type, user_id):
        if id_type == 'id':
            user = User.query.filter_by(id=int(user_id)).first()
        elif id_type == 'nic':
            user = User.query.filter_by(nic=user_id).first()
        else:
            api.abort(400, f"Invalid request")
        
        if not user:
            api.abort(404, f"User {user_id} does not exist")

        subject = user.nic
        with ory_hydra_client.ApiClient(configuration) as api_client:
            hydra = ory_hydra_client.AdminApi(api_client)
            try:
                # Revokes Consent Sessions of a Subject for a Specific OAuth 2.0 Client
                hydra.revoke_consent_sessions(subject, client='pehchan', all=True)
            except ory_hydra_client.ApiException as e:
                print("Exception when calling AdminApi->revoke_consent_sessions: %s\n" % e)
        db.session.delete(user)
        db.session.commit()
        return {
            'success': True
        }, 201

    def put(self, id_type, user_id):
        if id_type == 'id':
            user = User.query.filter_by(id=int(user_id)).first()
        elif id_type == 'nic':
            user = User.query.filter_by(nic=user_id).first()
        else:
            api.abort(400, f"Invalid request")
        
        if not user:
            api.abort(404, f"User {user_id} does not exist")

        # get payload
        post_data = request.get_json()
        if post_data.get('password') is None:
            api.abort(400, f"Invalid or missing password")

        user.password = post_data.get('password', '')
        db.session.commit()
        return {
            'success': True
        }, 201


class UsersList(Resource):
    
    @api.marshal_with(user, as_list=True)
    def get(self):
        return User.query.all(), 200

    @api.expect(user, validate=True)
    def post(self):
        post_data = request.get_json()
        nic = post_data.get('nic')
        name = post_data.get('name')
        email = post_data.get('email')
        phone = post_data.get('phone')
        password = post_data.get('password')
        challenge = post_data.get('login_challenge', None)
        remember = post_data.get('remember', False)
        response_object = {}

        if challenge is None:
            return {'message': 'Invalid or missing challenge!'}, 400

        user = User.query.filter_by(nic=nic).first()
        if user:
            response_object['message'] = 'Sorry. That NIC already exists.'
            return response_object, 400

        db.session.add(User(
            nic=nic,
            name=name,
            phone=phone,
            email=email,
            password=password))
        db.session.commit()

        response_object['message'] = f'{nic} was added!'
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
        response_object['redirect_to'] = response.redirect_to
        return response_object, 201



class VerifyUser(Resource):

    def get(self, nic, code):
        user = User.query.filter_by(nic=nic).first()
        if not user:
            api.abort(404, f"User {nic} does not exist")
        
        paigham_resp = get(paigham_url+f'/auth/verify-number?recipient={user.phone}&code={code}', headers={
            'X-API-Key': paigham_key
        })
        return {
            'verify': paigham_resp.json().get('verify')
        }, 200


class SendVerifyCode(Resource):

    def get(self, nic):
        user = User.query.filter_by(nic=nic).first()
        if not user:
            api.abort(404, f"User {nic} does not exist")
        
        paigham_resp = get(paigham_url+f'/auth/send-verify-code?recipient={user.phone}', headers={
            'X-API-Key': paigham_key
        })

        return {
            'success': True
        }, 200


class UserInfo(Resource):

    @api.marshal_with(user)
    def get(self):
        
        # Configure OAuth2 access token for authorization: oauth2
        configuration_public = ory_hydra_client.Configuration(
            host="https://hydra-public.pehchaan.kpgov.tech"
        )
        configuration_public.access_token = request.headers.get('access_token', '')

        with ory_hydra_client.ApiClient(configuration_public) as api_client:
            api_instance = public_api.PublicApi(api_client)
            try:
                api_response = api_instance.userinfo()
                user = User.query.filter_by(nic=str(api_response.sub)).first()
                if not user:
                    api.abort(404, f"User {api_response.sub} does not exist")
                return user, 200
            except ory_hydra_client.ApiException as e:
                print("Exception when calling PublicApi->userinfo: %s\n" % e)
        return {
            'success': False
        }, 200


api.add_resource(UsersList, '/users')
api.add_resource(UserInfo, '/usersinfo')
api.add_resource(Users, '/users/<id_type>/<user_id>')
api.add_resource(SendVerifyCode, '/send-verify-code/<nic>')
api.add_resource(VerifyUser, '/verify-number/<nic>/<code>')
