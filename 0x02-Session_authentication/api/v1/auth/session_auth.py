#!/usr/bin/env python3
'''Implement Session Authentication'''
from .auth import Auth
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    '''defines methods and attributes for implementing
    session authentication'''
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        '''create a session ID for a user_id

        Args:
            user_id (str, optional): User id. Defaults to None.

        Returns:
            str: a uuid for user
        '''
        if user_id is None or not isinstance(user_id, str):
            return None

        session_id = str(uuid4())

        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        '''returns user_id based on session id

        Args:
            session_id (str, optional): current session id. Defaults to None.

        Returns:
            str: user associated with session
        '''
        if session_id is None or not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        '''overloaded method to return User instance based on a cookie value

        Args:
            request (obj, optional): request. Defaults to None.
        '''
        if request is None:
            return

        session_id = self.session_cookie(request)

        if session_id is None:
            return None

        user_id = self.user_id_for_session_id(session_id)

        return User.get(user_id)

    def destroy_session(self, request=None):
        '''_summary_

        Args:
            request (_type_, optional): _description_. Defaults to None.
        '''
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_id = self.user_id_for_session_id(session_id)

        if not user_id:
            return False

        try:
            del self.user_id_by_session_id[session_id]
        except Exception:
            pass

        return True
