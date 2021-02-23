from flask import Blueprint, request, jsonify
from flask_restx import Resource, Api, fields
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from src import db
from src import jwt
from src.api.models import User


users_blueprint = Blueprint('users', __name__)
api = Api(users_blueprint)

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


class UsersList(Resource):
    
    @api.marshal_with(user, as_list=True)
    @jwt_required
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
        response_object = {}

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
        return response_object, 201


api.add_resource(UsersList, '/users')
api.add_resource(Users, '/users/<int:user_id>')
