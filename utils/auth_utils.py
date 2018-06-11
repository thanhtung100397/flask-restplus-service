from flask_jwt_extended import verify_jwt_in_request, verify_jwt_refresh_token_in_request, get_jwt_claims
from flask_jwt_extended.exceptions import NoAuthorizationError
from jwt import ExpiredSignatureError, InvalidSignatureError
from contants.constants import RoleContants
from functools import wraps


def requiredRefreshToken(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_refresh_token_in_request()
        except NoAuthorizationError:
            return {'message': 'Required bearer refresh token'}, 401
        except InvalidSignatureError:
            return {'message': 'Refresh token invalid'}, 401
        except ExpiredSignatureError:
            return {'message': 'Refresh token expired'}, 401
        return fn(*args, **kwargs)

    return wrapper


def requiredAuthenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            return {'message': 'Required bearer access token'}, 401
        except InvalidSignatureError:
            return {'message': 'Access token invalid'}, 401
        except ExpiredSignatureError:
            return {'message': 'Access token expired'}, 401
        return fn(*args, **kwargs)
    return wrapper


def requiredUserAuthenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            return {'message': 'Required bearer access token'}, 401
        except InvalidSignatureError:
            return {'message': 'Access token invalid'}, 401
        except ExpiredSignatureError:
            return {'message': 'Access token expired'}, 401
        jwt_role = get_jwt_claims()['role']
        if jwt_role != RoleContants.USER_ROLE:
            return {'message': 'Role is not ' + RoleContants.USER_ROLE}, 401
        return fn(*args, **kwargs)
    return wrapper


def requiredAdminAuthenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            return {'message': 'Required bearer access token'}, 401
        except InvalidSignatureError:
            return {'message': 'Access token invalid'}, 401
        except ExpiredSignatureError:
            return {'message': 'Access token expired'}, 401
        jwt_role = get_jwt_claims()['role']
        if jwt_role != RoleContants.ADMIN_ROLE:
            return {'message': 'Role is not ' + RoleContants.ADMIN_ROLE}, 401
        return fn(*args, **kwargs)
    return wrapper
