import secrets
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
import bcrypt
from sqlalchemy.sql import exists

from app import app, ma, db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    username = db.Column(db.String(16), unique=True, nullable=False)
    email = db.Column(db.String(48), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

    sessions = db.relationship("Session")

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    def check_password(self, password):
        return bcrypt.checkpw(password.encode(), self.password)


class UserSchema(ma.Schema):
    picture = ma.Method("get_picture_for_user")

    def get_picture_for_user(self, obj: User):
        return "https://www.gravatar.com/avatar/" + hashlib.md5(obj.email.lower().encode()).hexdigest() + "?d=mm"

    class Meta:
        fields = ('id', 'username', "picture")


class UserSchemaSelf(UserSchema):
    class Meta:
        fields = ('id', 'username', "picture", "email")


class Session(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    expires = db.Column(db.DateTime, nullable=False)
    token = db.Column(db.String(64), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, user: User = None, days=60):
        if user:
            self.user_id = user.id
            self.authenticated = True
        else:
            self.user_id = None
            self.authenticated = False
        self.token = secrets.token_hex(64)
        self.expires = datetime.today() + timedelta(days=days)

    def get_string_cookie(self):
        """
        :return: Cookie string
        """
        return self.token

    @staticmethod
    def verify(cookie: str):
        """
        Check if the provided cookie is part of a valid session.
        :param cookie: String cookie
        :return: a Session object when the session cookie was valid, False if
            the session cookie was invalid
        """
        if cookie:
            if db.session.query(exists().where(Session.token == cookie)).scalar():
                session = Session.query.filter_by(token=cookie).scalar()
                if session.expires > datetime.now() and not session.revoked:
                        return session

        return False


    def __repr__(self):
        return f'<Session {self.id}>'
