from flask_restplus import Api
from controllers.auth_controller import authNameSpace
from controllers.admin_controller import adminNamespace
from controllers.user_controller import userNamespace

api = Api()
api.add_namespace(authNameSpace)
api.add_namespace(adminNamespace)
api.add_namespace(userNamespace)

