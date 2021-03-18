from sqlalchemy.sql import func

from src import db


class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nic = db.Column(db.String(13), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(16), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    active = db.Column(db.Boolean(), default=False, nullable=False)
    verified = db.Column(db.Boolean(), default=False, nullable=False)
    created_date = db.Column(db.DateTime, default=func.now(), nullable=False)
    modified_date = db.Column(db.DateTime, default=func.now(), nullable=False)

    def __init__(self, nic, name, phone, email, password):
        self.nic = nic
        self.name = name
        self.phone = phone
        self.email = email
        self.password = password
