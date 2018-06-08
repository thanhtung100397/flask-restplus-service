from flask_jwt_extended import verify_jwt_in_request, get_jwt_claims
from flask_jwt_extended.exceptions import JWTExtendedException
from contants.constants import RoleContants
from functools import wraps


def requiredAuthenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except JWTExtendedException:
            return {'message': 'Access token missing or invalid'}, 401
        return fn(*args, **kwargs)
    return wrapper


def requiredUserAuthenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except JWTExtendedException:
            return {'message': 'Access token missing or invalid'}, 401
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
        except JWTExtendedException:
            return {'message': 'Access token missing or invalid'}, 401
        jwt_role = get_jwt_claims()['role']
        if jwt_role != RoleContants.ADMIN_ROLE:
            return {'message': 'Role is not ' + RoleContants.ADMIN_ROLE}, 401
        return fn(*args, **kwargs)
    return wrapper
