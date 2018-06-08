from datetime import timedelta

class DatabaseConstants:
    dbms = 'mysql'
    username = 'root'
    password = '1111'
    address = 'localhost'
    port = 3306
    databaseName = 'test_database'
    databaseUrl = dbms + '://' + username + ':' + password + '@' + address + ':' + str(port) + '/' + databaseName


class AuthenticationConstants:
    accessTokenExpiredDeltaTime = timedelta(minutes=15)
    refreshTokenExpiredDeltaTime = timedelta(hours=1)


class RoleContants:
    USER_ROLE = 'USER'
    ADMIN_ROLE = 'ADMIN'
