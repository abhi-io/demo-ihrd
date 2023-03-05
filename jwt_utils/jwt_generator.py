# -*- coding: utf-8 -*-
from datetime import datetime
from datetime import timedelta

import jwt

from jwt_utils.encryption import AESCipher
from ihrd.settings import JWT_ALGORITHM

FORMAT = "%Y-%m-%d %H:%M:%S"


def jwt_generator(user_id, jwt_secret, jwt_ttl, token_type, is_admin):
    current_time = datetime.now()
    time = current_time.strftime(FORMAT)
    actual_exp = datetime.strptime(time, FORMAT)

    if jwt_ttl >= 0:
        exp_time = current_time + timedelta(milliseconds=jwt_ttl)
        exp_at = exp_time.strftime(FORMAT)
        actual_exp = datetime.strptime(exp_at, FORMAT)
    payload = {
        "user_id": user_id,
        "is_admin": is_admin,
        "type": token_type,
        "issued_at": time,
        "exp": actual_exp.timestamp(),
    }
    jwt_token = jwt.encode(payload, jwt_secret, JWT_ALGORITHM)
    # return jwt_token.decode()

    obj = AESCipher()
    encoded_token = obj.encrypt_token(jwt_token.encode('utf-8'))
    return encoded_token
