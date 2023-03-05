# -*- coding: utf-8 -*-
import re

from utils.message_utils import get_message

PASSWORD_PATTERN = "((?=.*[0-9])(?=.*[!@#$%&*s]).{6,20})"
EMAIL_REGEX = "^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,5}$"
FORMAT = "%Y-%m-%d %H:%M:%S"
MOBILE_REGEX = re.compile("[+](0/91)?[7-9][0-9]{9}")


def validate_password(password):
    return re.match(PASSWORD_PATTERN, password)


def validate_email(email):
    return re.match(EMAIL_REGEX, email)

def validate_phone(mobile_no):
    return MOBILE_REGEX.match(mobile_no)

# method to validate null or empty check
def validate_null_or_empty(input_field, code, error):
    error_dict = {}
    if isinstance(input_field, str):
        if input_field is None or input_field == "":
            error_dict["message"] = get_message(code)
            error_dict["code"] = code
            error.append(error_dict)
    elif isinstance(input_field, int):
        if input_field == 0:
            error_dict["message"] = get_message(code)
            error_dict["code"] = code
            error.append(error_dict)
    elif isinstance(input_field, float):
        if input_field == 0.0:
            error_dict["message"] = get_message(code)
            error_dict["code"] = code
            error.append(error_dict)
    else:
        if input_field is None or input_field == "" or len(input_field) == 0:
            error_dict["message"] = get_message(code)
            error_dict["code"] = code
            error.append(error_dict)

    return error
