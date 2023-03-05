# -*- coding: utf-8 -*-
from jwt_utils.jwt_validator import jwt_validator
from rest_framework import authentication
from rest_framework import exceptions
from users.models import Token


class JwtTokensAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        token_id = request.headers.get("Authorization", "")
        try:
            payload = jwt_validator(token_id)
            Token.objects.get(access_token=token_id, is_expired=0)
            return payload, None
        except Exception:
            raise exceptions.AuthenticationFailed(
                detail={"code": 401, "message": "Expired or Invalid Token"}
            )
