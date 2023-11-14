#!/usr/bin/env python3
'''athentication'''
from bcrypt import hashpw, gensalt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from bcrypt import checkpw
from uuid import uuid4
from typing import Union


def _hash_password(password: str) -> bytes:
    '''hash password
    Args:
        password (str): password
    Returns:
        bytes: hashed password
    '''
    return hashpw(password.encode('utf-8'), gensalt())


def _generate_uuid() -> str:
    '''returs a string representation of a new UUID'''
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        '''registers new users to database
        Args:
            email (str): user email
            password (str): user password
        Returns:
            User: Newly created User
        '''
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
        return new_user

    def valid_login(self, email: str, password: str) -> bool:
        '''validates credentials
        Args:
            email (str): user email
            password (str): user email
        Returns:
            bool: True if matches else False
        '''
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        encoded_password = password.encode()

        if checkpw(encoded_password, user_password):
            return True

        return False

    def create_session(self, email: str) -> Union[str, None]:
        '''get session id
        Args:
            email (str): user email
        Returns:
            str: session id
        '''
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        '''get user from session_id
        Args:
            session_id (str): session_id
        Returns:
            Union[User, None]: User object if found else None
        '''
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: str) -> None:
        '''Destroys user session i.e set session id attribute to None
        Args:
            user_id (str): user id
        '''
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        '''generate token for password
        Args:
            email (str): user email to send token
        Returns:
            str: generated token
        '''
        try:
            user = self._db.find_user_by(email=email)
        except (NoResultFound, InvalidRequestError):
            raise ValueError

        user.reset_token = _generate_uuid()
        return user.reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """update password

        Args:
            reset_token (str): user reset token
            password (str): new password

        Raises:
            ValueError: if user can't be found with reset_token

        Returns: None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except Exception:
            raise ValueError

        hashed_password = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=hashed_password,
            reset_token=None
        )
        return None
