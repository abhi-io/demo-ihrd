# -*- coding: utf-8 -*-
from datetime import datetime

from django.core.mail import send_mail
from django.template import loader

from ihrd.settings import logger, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD


def send_email(email, params):
    try:
        logger.info("--------------inside mail----------------------------")
        logger.info(str(datetime.now()))
        email_template_name = params.pop("html")
        subject = params.pop("subject")
        message = ""
        template = loader.get_template(email_template_name)
        html_message = template.render(params)
        send_mail(
            subject,
            message,
            EMAIL_HOST_USER,
            [email],
            fail_silently=False,
            auth_user=EMAIL_HOST_USER,
            auth_password=EMAIL_HOST_PASSWORD,
            html_message=html_message,
        )
        logger.info(datetime.now())
        logger.info("--------------send  mail----------------------------")
    except Exception as e:
        logger.info("-------------- error in sending mail----------------------------")
        logger.error(e)
