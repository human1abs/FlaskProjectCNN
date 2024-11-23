from sqlalchemy import delete
from werkzeug.exceptions import BadRequest
from werkzeug.security import check_password_hash, generate_password_hash

from db import db
from managers.auth import AuthManager
from models.cancer_check import CancerCheckModel
from models.enums import RoleType
from models.user import UserModel
from schemas.bases import BaseUserSchema


class UserManager:
    @staticmethod
    def register(user_data):

        user_data['password'] = generate_password_hash(user_data['password'], method='pbkdf2:sha256')
        user_data['role'] = RoleType.user.name
        user = UserModel(**user_data)

        try:
            db.session.add(user)
            db.session.flush()

            return AuthManager.encode_token(user)
        except Exception as ex:
            raise BadRequest(str(ex))

    @staticmethod
    def login(data):
        user = db.session.execute(db.select(UserModel).filter_by(email=data["email"])).scalar()
        if not user or not check_password_hash(user.password, data["password"]):
            raise BadRequest("Invalid username or password")
        return AuthManager.encode_token(user)

    @staticmethod
    def delete(id_):
        db.session.execute(delete(CancerCheckModel.__table__).where(CancerCheckModel.user_id == id_))
        db.session.execute(delete(UserModel.__table__).where(UserModel.id == id_))
        db.session.flush()

        return f"Your account was successfully deleted"


class AdminManager:
    @staticmethod
    def get_user(id_):
        user = db.session.execute(db.select(UserModel).filter_by(id=id_)).scalar()

        return BaseUserSchema().dump(user)

    @staticmethod
    def delete_user(id_):
        db.session.execute(delete(CancerCheckModel.__table__).where(CancerCheckModel.user_id == id_))
        db.session.execute(delete(UserModel.__table__).where(UserModel.id == id_))
        db.session.flush()

        return f"User with id: {id_} deleted successfully"



