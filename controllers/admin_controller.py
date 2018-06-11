from flask_restplus import Namespace, Resource, marshal
from sqlalchemy import exists

from contants.constants import RoleContants
from database.database import db_session
from models.entity.user_entity import user_model_template, User, update_user_model_template
from utils.auth_utils import requiredAdminAuthenticated

adminNamespace = Namespace('admins', description='APIS for users management')

bearAuthenticationHeader = adminNamespace.parser().add_argument('Authorization', type=str, location='headers')
user_model = adminNamespace.model('user_model', user_model_template)
update_user_model = adminNamespace.model('update_user_model', update_user_model_template)


@adminNamespace.route('/users')
class ListUsers(Resource):

    @requiredAdminAuthenticated
    @adminNamespace.expect(bearAuthenticationHeader)
    @adminNamespace.response(200, 'Get list users success', model=[user_model])
    @adminNamespace.response(401, 'Access token invalid or missing or role is not ' + RoleContants.ADMIN_ROLE)
    def get(self):
        users = User.query.all()
        return marshal(users, user_model_template), 200


@adminNamespace.route('/users/<string:user_id>')
class User(Resource):

    @requiredAdminAuthenticated
    @adminNamespace.expect(bearAuthenticationHeader)
    @adminNamespace.doc(params={'user_id': 'user id'})
    @adminNamespace.response(200, 'Get user success', model=user_model)
    @adminNamespace.response(404, 'User not found')
    @adminNamespace.response(401, 'Access token invalid or missing or role is not ' + RoleContants.ADMIN_ROLE)
    def get(self, user_id):
        user_found = User.query.filter(User.id == user_id).first()
        if user_found is None:
            return {'message': 'User not found'}, 404
        return marshal(user_found, user_model_template), 200

    @requiredAdminAuthenticated
    @adminNamespace.expect(bearAuthenticationHeader)
    @adminNamespace.expect(update_user_model, validate=True)
    @adminNamespace.doc(params={'user_id': 'updated user id'})
    @adminNamespace.response(200, 'Update user success')
    @adminNamespace.response(404, 'User not found')
    @adminNamespace.response(401, 'Access token invalid or missing or role is not ' + RoleContants.ADMIN_ROLE)
    def put(self, user_id):
        user_found = User.query.filter(User.id == user_id).first()
        if user_found is None:
            return {'message': 'User not found'}, 404
        payload = adminNamespace.payload
        if user_found.update(payload):
            db_session.commit()
        return {'message': 'user updated'}, 200

    @requiredAdminAuthenticated
    @adminNamespace.expect(bearAuthenticationHeader)
    @adminNamespace.doc(params={'user_id': 'deleted user id'})
    @adminNamespace.response(200, 'Delete user success')
    @adminNamespace.response(404, 'User not found')
    @adminNamespace.response(401, 'Access token invalid or missing or role is not ' + RoleContants.ADMIN_ROLE)
    def delete(self, user_id):
        if db_session.query(exists().where(User.id == user_id)).scalar() is not True:
            return {'message': 'User not found'}, 404
        User.query.filter(User.id == user_id).delete()
        db_session.commit()
        return {'message': 'User deleted'}, 200


