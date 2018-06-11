from flask_jwt_extended import get_jwt_identity
from flask_restplus import Namespace, Resource, marshal
from contants.constants import RoleContants
from database.database import db_session
from models.entity.user_entity import user_model_template, update_user_model_template, User
from utils.auth_utils import requiredUserAuthenticated

userNamespace = Namespace('users', description='APIS for user')

bearAuthenticationHeader = userNamespace.parser().add_argument('Authorization', type=str, location='headers')
user_model = userNamespace.model('user_model', user_model_template)
update_user_model = userNamespace.model('update_user_model', update_user_model_template)

@userNamespace.route('/profile')
class UserController(Resource):

    @requiredUserAuthenticated
    @userNamespace.expect(bearAuthenticationHeader)
    @userNamespace.response(200, 'Get user info success', model=user_model)
    @userNamespace.response(404, 'User deleted')
    @userNamespace.response(401, 'Access token invalid or missing or role is not ' + RoleContants.USER_ROLE)
    def get(self):
        username = get_jwt_identity()
        user_found = User.query.filter(User.username == username).first()
        if user_found is None:
            return {'message': 'user deleted'}, 404
        return marshal(user_found, user_model_template), 200

    @requiredUserAuthenticated
    @userNamespace.expect(bearAuthenticationHeader)
    @userNamespace.doc(params={'user_id': 'updated user id'},
             body=update_user_model)
    @userNamespace.response(200, 'Update success')
    @userNamespace.response(404, 'User deleted')
    @userNamespace.response(401, 'Access token invalid or missing or role is not ' + RoleContants.USER_ROLE)
    def put(self):
        username = get_jwt_identity()
        user_found = User.query.filter(User.username == username).first()
        if user_found is None:
            return {'message': 'User deleted'}, 404
        payload = userNamespace.payload
        if user_found.update(payload):
            db_session.commit()
        return {'message': 'user updated'}, 200
