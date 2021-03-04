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
    @jwt_required
    def get(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            api.abort(404, f"User {user_id} does not exist")
        return user, 200

    def delete(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            api.abort(404, f"User {user_id} does not exist")
        db.session.delete(user)
        db.session.commit()


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


api.add_resource(UsersList, '/users')
api.add_resource(Users, '/users/<int:user_id>')
