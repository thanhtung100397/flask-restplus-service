from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jwt_identity
from flask_restplus import Api, Resource, marshal
from sqlalchemy import exists
from database.database import db_session
from database.database import init_db
from models.entity.user_entity import User, user_model_template, new_user_model_template, update_user_model_template
from models.dto.authentication_dto import authentication_dto_template, AuthenticationResultDto, \
    authentication_result_template
from contants.constants import AuthenticationConstants, RoleContants
from utils.auth_utils import requiredUserAuthenticated, requiredAdminAuthenticated

app = Flask(__name__)
# config and init jwt
app.config['JWT_SECRET_KEY'] = 'my_jwt_secret_key'
jwt = JWTManager(app)

api = Api(app)


@jwt.user_claims_loader
def add_claim_to_access_token(username):
    role = User.query.with_entities(User.role).filter(User.username == username).scalar()
    return {'role': role}


bearAuthenticationHeader = api.parser().add_argument('Authorization', type=str, location='headers')

init_db()

################################################# AUTH #################################################################
authNameSpace = api.namespace('auth', description='APIS for authentication')


@authNameSpace.route('/login')
class LoginController(Resource):
    authentication_dto_model = api.model('authentication_model', authentication_dto_template)
    authentication_result_model = api.model('authentication_result_model', authentication_result_template)

    @api.expect(authentication_dto_model, validate=True)
    @api.response(200, 'Authentication success', model=authentication_result_model)
    def post(self):
        payload = api.payload
        username = payload['username']
        password = payload['password']
        role = User.query.with_entities(User.role).filter(User.username == username, User.password == password).scalar()
        if role is None:
            return {'message': 'wrong username or password'}, 401
        authentication_result_dto = AuthenticationResultDto
        authentication_result_dto.role = role
        authentication_result_dto.accessToken = create_access_token(identity=username,
                                                                    expires_delta=AuthenticationConstants.accessTokenExpiredDeltaTime)
        authentication_result_dto.refreshToken = create_refresh_token(identity=username,
                                                                      expires_delta=AuthenticationConstants.refreshTokenExpiredDeltaTime)
        return marshal(authentication_result_dto, authentication_result_template), 200


@authNameSpace.route('/users/register')
class UserRegisterController(Resource):
    new_user_model = api.model('new_user_model', new_user_model_template)

    @api.expect(new_user_model, validate=True)
    @api.response(201, 'Create user success')
    @api.response(409, 'Username exist')
    def post(self):
        payload = api.payload
        username = payload['username']
        if db_session.query(exists().where(User.username == username)).scalar():
            return {'message': 'username exist'}, 409
        new_user = User(payload=payload, role=RoleContants.USER_ROLE)
        db_session.add(new_user)
        db_session.commit()
        return {'message': 'user created'}, 201


@authNameSpace.route('/admins/register')
class UserRegisterController(Resource):
    new_user_model = api.model('new_user_model', new_user_model_template)

    @api.expect(new_user_model, validate=True)
    @api.response(201, 'Create admin success')
    @api.response(409, 'Username exist')
    def post(self):
        payload = api.payload
        username = payload['username']
        if db_session.query(exists().where(User.username == username)).scalar():
            return {'message': 'username exist'}, 409
        new_user = User(payload=payload, role=RoleContants.ADMIN_ROLE)
        db_session.add(new_user)
        db_session.commit()
        return {'message': 'admin created'}, 201


################################################# ADMIN ################################################################
userManagementNamespace = api.namespace('admins', description='APIS for users management')


@userManagementNamespace.route('/users')
class UsersController(Resource):
    user_model = api.model('user_model', user_model_template)

    @requiredAdminAuthenticated
    @api.expect(bearAuthenticationHeader)
    @api.response(200, 'Get list users success', model=[user_model])
    @api.response(401, 'Access token invalid or missing or role is not ' + RoleContants.ADMIN_ROLE)
    def get(self):
        users = User.query.all()
        return marshal(users, user_model_template), 200


@userManagementNamespace.route('/users/<string:user_id>')
class UsersWithIDPathController(Resource):
    user_model = api.model('user_model', user_model_template)
    update_user_model = api.model('update_user_model', update_user_model_template)

    @requiredAdminAuthenticated
    @api.expect(bearAuthenticationHeader)
    @api.doc(params={'user_id': 'user id'})
    @api.response(200, 'Get user success', model=user_model)
    @api.response(404, 'User not found')
    @api.response(401, 'Access token invalid or missing or role is not ' + RoleContants.ADMIN_ROLE)
    def get(self, user_id):
        user_found = User.query.filter(User.id == user_id).first()
        if user_found is None:
            return {'message': 'User not found'}, 404
        return marshal(user_found, user_model_template), 200

    @requiredAdminAuthenticated
    @api.expect(bearAuthenticationHeader)
    @api.expect(update_user_model, validate=True)
    @api.doc(params={'user_id': 'updated user id'})
    @api.response(200, 'Update user success')
    @api.response(404, 'User not found')
    @api.response(401, 'Access token invalid or missing or role is not ' + RoleContants.ADMIN_ROLE)
    def put(self, user_id):
        user_found = User.query.filter(User.id == user_id).first()
        if user_found is None:
            return {'message': 'User not found'}, 404
        payload = api.payload
        if user_found.update(payload):
            db_session.commit()
        return {'message': 'user updated'}, 200

    @requiredAdminAuthenticated
    @api.expect(bearAuthenticationHeader)
    @api.doc(params={'user_id': 'deleted user id'})
    @api.response(200, 'Delete user success')
    @api.response(404, 'User not found')
    @api.response(401, 'Access token invalid or missing or role is not '+RoleContants.ADMIN_ROLE)
    def delete(self, user_id):
        if db_session.query(exists().where(User.id == user_id)).scalar() is not True:
            return {'message': 'User not found'}, 404
        User.query.filter(User.id == user_id).delete()
        db_session.commit()
        return {'message': 'User deleted'}, 200


################################################### USER ###############################################################
userNamespace = api.namespace('users', description='APIS for user')


@userNamespace.route('/profile')
class UserController(Resource):
    user_model = api.model('user_model', user_model_template)
    update_user_model = api.model('update_user_model', update_user_model_template)

    @requiredUserAuthenticated
    @api.expect(bearAuthenticationHeader)
    @api.response(200, 'Get user info success', model=user_model)
    @api.response(404, 'User deleted')
    @api.response(401, 'Access token invalid or missing or role is not ' + RoleContants.USER_ROLE)
    def get(self):
        username = get_jwt_identity()
        user_found = User.query.filter(User.username == username).first()
        if user_found is None:
            return {'message': 'user deleted'}, 404
        return marshal(user_found, user_model_template), 200

    @requiredUserAuthenticated
    @api.expect(bearAuthenticationHeader)
    @api.doc(params={'user_id': 'updated user id'},
             body=update_user_model)
    @api.response(200, 'Update success')
    @api.response(404, 'User deleted')
    @api.response(401, 'Access token invalid or missing or role is not ' + RoleContants.USER_ROLE)
    def put(self):
        username = get_jwt_identity()
        user_found = User.query.filter(User.username == username).first()
        if user_found is None:
            return {'message': 'User deleted'}, 404
        payload = api.payload
        if user_found.update(payload):
            db_session.commit()
        return {'message': 'user updated'}, 200


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
