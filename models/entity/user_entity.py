from flask_restplus import fields
from sqlalchemy import Column, Integer, String, Date
from database.database import Base
from utils.utils import format_date

user_model_template = {
    'id': fields.Integer,
    'username': fields.String(description='username of user account'),
    'password': fields.String(description='password of user account'),
    'fullName': fields.String(description='full name of user'),
    'dateOfBirth': fields.Date(description='date of birth of user, yyyy-MM-dd')
}

new_user_model_template = {
    'username': fields.String(description='username of user account', required=True, min_length=1),
    'password': fields.String(description='password of user account', required=True, min_length=6),
    'fullName': fields.String(description='full name of user', required=True, min_length=1),
    'dateOfBirth': fields.Date(description='date of birth of user, yyyy-MM-dd', required=True)
}

update_user_model_template = {
    'fullName': fields.String(description='full name of user', required=True, min_length=1),
    'dateOfBirth': fields.Date(description='date of birth of user, yyyy-MM-dd', required=True)
}


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    username = Column(String(45), unique=True, nullable=False)
    password = Column(String(45), nullable=False)
    fullName = Column(String(70), nullable=False)
    dateOfBirth = Column(Date, nullable=False)
    role = Column(String(45), nullable=False)

    def __init__(self, username=None, password=None, fullName=None, dateOfBirth=None, role=None):
        self.username = username
        self.password = password
        self.fullName = fullName
        self.dateOfBirth = dateOfBirth
        self.role = role

    def __init__(self, payload, role = None):
        self.username = payload['username']
        self.password = payload['password']
        self.fullName = payload['fullName']
        self.dateOfBirth = payload['dateOfBirth']
        self.role = role

    def update(self, payload):
        is_modified = False
        if payload['fullName'] is not None:
            self.fullName = payload['fullName']
            is_modified = True
        if payload['dateOfBirth'] is not None:
            self.dateOfBirth = payload['dateOfBirth']
            is_modified = True
        return is_modified

    def __repr__(self) -> str:
        return 'User: {id = ' + str(self.id) + \
               ', username = ' + self.username + \
               ', password = ' + self.password + \
               ', fullName = ' + self.fullName + \
               ', dateOfBirth = ' + format_date(self.dateOfBirth) + '}'
