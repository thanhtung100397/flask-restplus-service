from flask import Flask
from flask_jwt_extended import JWTManager
from core.init import api
from database.database import db_session, init_db
from models.entity.user_entity import User

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'my_jwt_secret_key'
jwt = JWTManager(app)

init_db()


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


@jwt.user_claims_loader
def add_claim_to_access_token(username):
    role = User.query.with_entities(User.role).filter(User.username == username).scalar()
    return {'role': role}


api.init_app(app)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
