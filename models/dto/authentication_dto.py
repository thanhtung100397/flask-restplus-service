from flask_restplus import fields

authentication_dto_template = {
    'username': fields.String(description='Username of user', required=True, min_length=1),
    'password': fields.String(description='Password of user', required=True, min_length=1)
}

authentication_result_template = {
    'accessToken': fields.String(description='Access token of user'),
    'refreshToken': fields.String(description='Refresh token of user'),
    'role': fields.String(description='Role of user')
}


class AuthenticationResultDto:
    accessToken = None
    refreshToken = None
    role = None
