# -*- coding: utf-8 -*-
"""
class used for jwt validator
"""
import jwt
from rest_framework import exceptions

from jwt_utils.encryption import AESCipher
from ihrd.settings import JWT_ALGORITHM, JWT_SECRET

jwt_secret = JWT_SECRET
options = {"verify_exp": True}


def jwt_validator(token):
    try:
        obj = AESCipher()
        decoded = obj.decrypt_token(token.encode('utf-8'))
        payload = jwt.decode(
            decoded, jwt_secret, algorithms=JWT_ALGORITHM, options=options
        )
        return payload
    except Exception as e:
        raise exceptions.AuthenticationFailed
