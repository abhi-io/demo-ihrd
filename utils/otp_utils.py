# -*- coding: utf-8 -*-
import random

from django.contrib.auth import get_user_model
from twilio.rest import Client

from ihrd import settings


def generate_otp():
    return random.randint(1000, 9999)


def send_verification(phone_number):
    try:
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        client = Client(account_sid, auth_token)
        digits = set(range(10))
        # We generate a random integer, 1 <= first <= 9
        first = random.randint(1, 9)
        # We remove it from our set, then take a sample of
        # 3 distinct elements from the remaining values
        last_3 = random.sample(digits - {first}, 3)
        code = str(first) + ''.join(map(str, last_3))

        body = "your verification number is" + code
        message = client.messages.create(
            from_=settings.TWILIO_PHONE_FROM,
            body=body,
            to=phone_number

        )
        get_user_model().objects.filter(phone_number=phone_number).update(verification_code=code)

    except:
        return 1
