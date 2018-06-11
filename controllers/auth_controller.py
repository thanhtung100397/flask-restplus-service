from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity
from flask_restplus import Resource, marshal, Namespace
from sqlalchemy import exists
from contants.constants import AuthenticationConstants, RoleContants
from database.database import db_session
from models.dto.authentication_dto import authentication_dto_template, authentication_result_template, \
    AuthenticationResultDto, access_token_result_template, AccessToeknResultDto
from models.entity.user_entity import User, new_user_model_template
from utils.auth_utils import requiredRefreshToken

authNameSpace = Namespace('auth', description='authNameSpaceS for authentication')

bearAuthenticationHeader = authNameSpace.parser().add_argument('Authorization', type=str, location='headers')


@authNameSpace.route('/login')
class Login(Resource):
    authentication_dto_model = authNameSpace.model('authentication_model', authentication_dto_template)
    authentication_result_model = authNameSpace.model('authentication_result_model', authentication_result_template)

    @authNameSpace.expect(authentication_dto_model, validate=True)
    @authNameSpace.response(200, 'Authentication success', model=authentication_result_model)
    def post(self):
        payload = authNameSpace.payload
        username = payload['username']
        password = payload['password']
        role = User.query.with_entities(User.role).filter(User.username == username, User.password == password).scalar()
        if role is None:
            return {'message': 'wrong username or password'}, 401
        authentication_result_dto = AuthenticationResultDto
        authentication_result_dto.role = role
        authentication_result_dto.accessToken = create_access_token(identity=username,
                                                                    expires_delta=AuthenticationConstants
                                                                    .accessTokenExpiredDeltaTime)
        authentication_result_dto.refreshToken = create_refresh_token(identity=username,
                                                                      expires_delta=AuthenticationConstants
                                                                      .refreshTokenExpiredDeltaTime)
        return marshal(authentication_result_dto, authentication_result_template), 200
    
    
@authNameSpace.route('/users/register')
class UserRegistration(Resource):
    new_user_model = authNameSpace.model('new_user_model', new_user_model_template)

    @authNameSpace.expect(new_user_model, validate=True)
    @authNameSpace.response(201, 'Create user success')
    @authNameSpace.response(409, 'Username exist')
    def post(self):
        payload = authNameSpace.payload
        username = payload['username']
        if db_session.query(exists().where(User.username == username)).scalar():
            return {'message': 'username exist'}, 409
        new_user = User(payload=payload, role=RoleContants.USER_ROLE)
        db_session.add(new_user)
        db_session.commit()
        return {'message': 'user created'}, 201


@authNameSpace.route('/admins/register')
class AdminRegistration(Resource):
    new_user_model = authNameSpace.model('new_user_model', new_user_model_template)

    @authNameSpace.expect(new_user_model, validate=True)
    @authNameSpace.response(201, 'Create admin success')
    @authNameSpace.response(409, 'Username exist')
    def post(self):
        payload = authNameSpace.payload
        username = payload['username']
        if db_session.query(exists().where(User.username == username)).scalar():
            return {'message': 'username exist'}, 409
        new_user = User(payload=payload, role=RoleContants.ADMIN_ROLE)
        db_session.add(new_user)
        db_session.commit()
        return {'message': 'admin created'}, 201


@authNameSpace.route('/newAccessToken')
class NewAccessToken(Resource):
    access_token_result_model = authNameSpace.model('access_token_result_model', access_token_result_template)

    @requiredRefreshToken
    @authNameSpace.expect(bearAuthenticationHeader)
    @authNameSpace.response(200, 'Create new access token success', model=access_token_result_model)
    @authNameSpace.response(401, 'Refresh token invalid or missing')
    def get(self):
        username = get_jwt_identity()
        access_token_result_dto = AccessToeknResultDto
        access_token_result_dto.accessToken = create_access_token(identity=username,
                                                                  expires_delta=AuthenticationConstants
                                                                  .accessTokenExpiredDeltaTime)
        return marshal(access_token_result_dto, access_token_result_template), 200

