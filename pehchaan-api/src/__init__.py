import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)


# instantiate the db
db = SQLAlchemy()
jwt = JWTManager()


def create_app(script_info=None):

    # instantiate the app
    app = Flask(__name__)

    # set config
    app_settings = os.getenv('APP_SETTINGS')
    app.config.from_object(app_settings)

    # set up extensions
    db.init_app(app)

    # set up JWT
    jwt.init_app(app)

    # register blueprints
    from src.api.users import users_blueprint
    app.register_blueprint(users_blueprint)

    from src.api.auth import auth_blueprint
    app.register_blueprint(auth_blueprint)

    # shell context for flask cli
    @app.shell_context_processor
    def ctx():
        return {
            'app': app, 'db': db
        }
    
    return app
