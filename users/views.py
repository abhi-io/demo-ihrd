# -*- coding: utf-8 -*-
import itertools
import uuid
from datetime import datetime
from datetime import timedelta
from threading import Thread


from authentication.authentication import JwtTokensAuthentication
from basicauth import decode
from basicauth import encode
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import F, DateField
from django.db.models.functions import Cast
from django.utils import timezone
from django.views.decorators.cache import cache_control

from core_viewsets.custom_viewsets import CreateViewSet, ListCreateViewSet, ListViewSet, FetchUpdateViewSets
from jwt_utils.jwt_generator import jwt_generator
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response
from users.models import  Token
from users.models import UserNote
from utils.datetime_utils import calculate_time_difference
from utils.datetime_utils import convert_str_date
from utils.datetime_utils import convert_to_str_time
from utils.mail_utils import send_email
from utils.message_utils import get_message
from utils.otp_utils import send_verification
from utils.pagination import CustomPageNumberPagination
from utils.upload import upload_file_to_s3
from utils.validation_utils import validate_email, validate_phone
from utils.validation_utils import validate_null_or_empty
from utils.validation_utils import validate_password

from .serializers import EmptySerializer, LoginSerializer
from .serializers import RegisterSerializer
from .serializers import ResetPasswordSerializer
from .serializers import UserNotesSerializer
from .serializers import UserSerializer
from ihrd.settings import logger, RESET_PASSWORD_LINK, JWT_SECRET, TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY, \
    BASIC_TEMPLATE_IMAGE_URL, BASIC_IMAGE_URL


# Create your views here.


class RegisterViewSet(CreateViewSet):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = RegisterSerializer
    queryset = get_user_model().objects.all()

    def create(self, request, *args, **kwargs):

        email = request.data.get("email")
        user_name = request.data.get("username", "")
        password = request.data.get("password", None)

        # display what are the fields which tent to empty.
        validations = []
        validations = validate_null_or_empty(email, 307, validations)
        validations = validate_null_or_empty(password, 305, validations)
        validations = validate_null_or_empty(user_name, 304, validations)

        if len(validations) > 0:
            resp = {}
            resp["code"] = 600
            resp["validations"] = validations
            return Response(resp, status=status.HTTP_412_PRECONDITION_FAILED)

        if not validate_email(email):
            return Response(
                {"code": 604, "message": get_message(604)},
                status=status.HTTP_412_PRECONDITION_FAILED,
            )

        if not validate_password(password):
            return Response(
                {"code": 618, "message": get_message(618)},
                status=status.HTTP_412_PRECONDITION_FAILED,
            )

        user_obj = get_user_model().objects.filter(email=email).count()
        if user_obj >= 1:
            return Response(
                {"code": 621, "message": get_message(621)},
                status=status.HTTP_412_PRECONDITION_FAILED,
            )

        user = get_user_model().objects.create_user(request.data)
        # t = Thread(target=send_verification, args=(phone_number,))
        # t.start()

        return Response(
            {"code": 200, "message": get_message(200), "user_id": user._get_pk_val()}
        )


class LoginViewSet(CreateViewSet):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")
        # display what are the fields which tent to empty.
        validations = []
        validations = validate_null_or_empty(email, 307, validations)
        validations = validate_null_or_empty(password, 305, validations)

        if len(validations) > 0:
            resp = {}
            resp["code"] = 600
            resp["validations"] = validations
            return Response(resp, status=status.HTTP_412_PRECONDITION_FAILED)
        try:
            # user_obj = get_user_model().objects.get(email=email, is_verified=True)
            user_obj = get_user_model().objects.get(email=email)
            valid = user_obj.check_password(password)

            if not valid:
                # logger.error({"code": 503, "message": get_message(503)})
                return Response(
                    {"code": 503, "message": get_message(503)},
                    status.HTTP_412_PRECONDITION_FAILED,
                )
            access_token = jwt_generator(
                user_obj.id,
                JWT_SECRET,
                TOKEN_EXPIRY,
                "access",
                user_obj.is_superuser,
            )
            refresh_token = jwt_generator(
                user_obj.id,
                JWT_SECRET,
                REFRESH_TOKEN_EXPIRY,
                "refresh",
                user_obj.is_superuser,
            )
            Token.objects.filter(user_id=user_obj).update(is_expired=1)

            Token.objects.update_or_create(
                user_id=user_obj,
                access_token=access_token,
                refresh_token=refresh_token,
                defaults={"updated_at": timezone.now()},
            )
            log_obj, updated_flag = LoginLog.objects.update_or_create(
                user_id=user_obj,
                defaults={
                    "updated_at": timezone.now(),
                    "last_logged_in": timezone.now(),
                },
            )
            log_obj.login_count = log_obj.login_count + 1
            log_obj.save()
            return Response(
                {
                    "code": 200,
                    "message": get_message(200),
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user_id": user_obj.pk,
                    "email": user_obj.email,
                    "user_type": user_obj.user_type,
                }
            )

        except ObjectDoesNotExist as ex:
            logger.error(ex)
            return Response(
                {"code": 204, "message": get_message(204)},
                status.HTTP_400_BAD_REQUEST,
            )


class UserViewSet(FetchUpdateViewSets):
    authentication_classes = [JwtTokensAuthentication]
    pagination_class = CustomPageNumberPagination
    serializer_class = UserSerializer
    queryset = get_user_model().objects.all().exclude(is_superuser=1)

    @cache_control(max_age=0)
    def list(self, request, *args, **kwargs):
        email = request.query_params.get("email", None)
        user_id = request.user.get("user_id")
        queryset = self.get_queryset().exclude(pk=user_id)
        if email:
            queryset = queryset.filter(email__icontains=email)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
        # if request.user.get("is_admin", False):
        #     return super().list(request)
        # return Response({"code": 200, "message": get_message(200), "results": [], "count": 0})

    def retrieve(self, request, *args, **kwargs):
        user_id = request.user.get("user_id")
        print(user_id)
        try:
            instance = get_user_model().objects.get(pk=user_id, is_verified=True)
            serializer = self.get_serializer(instance)
            return Response(serializer.data)

        except ObjectDoesNotExist as ex:
            logger.error(ex)
            return Response(
                {"code": 400, "message": get_message(400)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as ex:
            logger.error(ex)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        user_id = request.user.get("user_id")
        user_image = request.data.get("image_url")
        image_name = request.data.get("image_name", "")
        try:
            user_obj = get_user_model().objects.get(pk=user_id, is_verified=True)
            user_obj.image_url = user_image
            user_obj.image_name = image_name
            user_obj.updated_at = timezone.now()
            user_obj.save()

            return Response({"code": 200, "message": get_message(200)})
        except Exception as ex:
            logger.error(ex)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LogoutViewSet(CreateViewSet):
    permission_classes = ()
    authentication_classes = [JwtTokensAuthentication]
    serializer_class = EmptySerializer

    def create(self, request, *args, **kwargs):
        user_id = request.user.get("user_id")
        token_id = request.headers.get("Authorization", "")
        try:
            get_user_model().objects.get(pk=user_id, is_verified=True)
        except ObjectDoesNotExist as ex:
            logger.error(ex)
            return Response(
                {"code": 204, "message": get_message(204)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token_obj = Token.objects.get(access_token=token_id, user_id=user_id)
            token_obj.is_expired = 1
            token_obj.save()
            return Response({"code": 200, "message": get_message(200)})
        except Exception as ex:
            logger.error(ex)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ForgotPasswordViewSet(CreateViewSet):
    permission_classes = ()
    authentication_classes = ()
    serializer_class = EmptySerializer

    def create(self, request, *args, **kwargs):

        email_id = request.data.get("email")
        try:
            user_obj = get_user_model().objects.get(email=email_id, is_verified=True)
        except ObjectDoesNotExist as ex:
            logger.error(ex)
            return Response(
                {"code": 204, "message": get_message(204)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            current_time = timezone.now()
            exp_time = current_time + timedelta(milliseconds=1800000)
            exp_at = exp_time.strftime("%Y-%m-%d %H:%M:%S")

            token_url = encode(user_obj.email, exp_at)
            token = token_url.split("Basic ")
            reset_url = RESET_PASSWORD_LINK + "token=" + str(token[1])

            messages = {
                "first_name": user_obj.first_name,
                "last_name": user_obj.last_name,
                "name_email": user_obj.email,
                "name": user_obj.email,
                "image_logo": BASIC_TEMPLATE_IMAGE_URL,
                "font_path": BASIC_IMAGE_URL,
                "html": "users/forgot_password_email.html",
                "reset_url": reset_url,
                "subject": "Reset Password Link",
            }
            # send_email(email_id, messages)
            mail_thread = Thread(target=send_email, args=(email_id, messages))
            mail_thread.start()
            return Response(
                {
                    "code": 200,
                    "message": "A password reset mail is send to the registered email",
                }
            )

        except Exception as ex:
            logger.error(ex)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ResetPasswordViewSet(CreateViewSet):
    permission_classes = ()
    authentication_classes = ()
    serializer_class = ResetPasswordSerializer

    def create(self, request, *args, **kwargs):
        password = request.data.get("password")
        token = request.data.get("token")
        try:
            token = token.replace("%20", "")
            token = "Basic " + token
            email, exp_at = decode(token)
        except Exception as ex:
            logger.error(ex)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        try:

            user_obj = get_user_model().objects.get(email=email, is_verified=True)
        except ObjectDoesNotExist as ex:
            logger.error(ex)
            return Response(
                {"code": 204, "message": get_message(204)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:

            current_time = timezone.now()
            time_difference = calculate_time_difference(
                exp_at, convert_to_str_time(current_time)
            )

            if time_difference < 0:
                return Response(
                    {"code": 206, "message": get_message(206)},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not validate_password(password):
                return Response({"code": 618, "message": get_message(618)})

            valid = user_obj.check_password(password)

            if valid:
                # logger.error({"code": 503, "message": get_message(503)})
                return Response(
                    {"code": 311, "message": get_message(311)},
                    status.HTTP_412_PRECONDITION_FAILED,
                )

            user_obj.set_password(password)
            user_obj.updated_at = timezone.now()
            user_obj.save()
            return Response({"code": 200, "message": get_message(200)})
        except Exception as ex:
            logger.error(ex)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ChangePasswordViewSet(CreateViewSet):
    permission_classes = ()
    authentication_classes = [
        JwtTokensAuthentication,
    ]
    serializer_class = EmptySerializer

    def create(self, request, *args, **kwargs):
        current_password = request.data.get("current_password", "")
        new_password = request.data.get("new_password", "")
        user_id = request.user.get("user_id")
        try:
            user_obj = get_user_model().objects.get(id=user_id, is_verified=True)
        except ObjectDoesNotExist as e:
            logger.error(e)
            return Response(
                {"code": 204, "message": get_message(204)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            if current_password == new_password:
                return Response(
                    {"code": 311, "message": get_message(311)},
                    status.HTTP_412_PRECONDITION_FAILED,
                )

            valid = user_obj.check_password(current_password)
            if not valid:
                return Response(
                    {"code": 619, "message": get_message(619)},
                    status=status.HTTP_412_PRECONDITION_FAILED,
                )

            if not validate_password(new_password):
                return Response(
                    {"code": 618, "message": get_message(618)},
                    status=status.HTTP_412_PRECONDITION_FAILED,
                )

            user_obj.set_password(new_password)
            user_obj.updated_at = timezone.now()
            user_obj.save()

            return Response({"code": 200, "message": get_message(200)})
        except Exception as e:
            logger.error(e)
            print(e)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UploadImageViewSet(CreateViewSet):
    permission_classes = ()
    serializer_class = EmptySerializer
    authentication_classes = [
        JwtTokensAuthentication,
    ]

    def get_queryset(self):
        pass

    def create(self, request, *args, **kwargs):
        try:
            image = request.data.get("name")
            directory_name = "user_images/"
            image_ext = str(image).split(".")[-1]
            image_name = uuid.uuid4().hex
            # name = directory_name + image_name + "." + image_ext
            # path = default_storage.save(name, ContentFile(image.read()))
            # os.path.join(settings.MEDIA_ROOT, path)
            # return Response({"code": 200, "message": get_message(200), "image_url": path})
            s3_image_name = directory_name + image_name + "." + image_ext
            # path = default_storage.save(s3_image_name, ContentFile(image.read()))
            # local_path = os.path.join(settings.MEDIA_ROOT, path)
            upload_url = upload_file_to_s3(s3_image_name, image)
            # upload_url = upload_file_to_s3_in_parts(s3_image_name, local_path)
            logger.info(upload_url)
            if upload_url:
                # os.remove(local_path)
                return Response(
                    {
                        "code": 200,
                        "message": get_message(200),
                        "image_url": upload_url,
                        "image_name": s3_image_name,
                    }
                )
            else:
                return Response(
                    {"code": 313, "message": get_message(313)},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            logger.error(e)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserNotesViewSet(viewsets.ModelViewSet):
    permission_classes = ()
    serializer_class = UserNotesSerializer
    pagination_class = CustomPageNumberPagination
    authentication_classes = [
        JwtTokensAuthentication,
    ]
    http_method_names = ['get', 'post', 'put', 'delete', 'head', 'options']

    def get_queryset(self):
        user_id = self.request.user.get("user_id")
        start_date = self.request.query_params.get("from")
        end_date = self.request.query_params.get("to")
        note_text = self.request.query_params.get("note_text")
        queryset = UserNote.objects.filter(user_id=user_id).order_by("-created_at")

        try:
            get_user_model().objects.get(id=user_id, is_verified=True)
        except ObjectDoesNotExist as e:
            logger.error(e)
            return queryset.none()
        if note_text:
            queryset = queryset.filter(note_text__icontains=note_text)

        if start_date:
            min_time = datetime.min.time()
            start_date = datetime.combine(convert_str_date(start_date), min_time)
            queryset = queryset.filter(created_at__gte=start_date)
        if end_date:
            max_time = datetime.max.time()
            end_date = datetime.combine(convert_str_date(end_date), max_time)
            queryset = queryset.filter(created_at__lte=end_date)

        return queryset

    def create(self, request, *args, **kwargs):
        user_id = request.user.get("user_id")
        note_text = request.data.get("note_text")

        # check content id exist in micro service
        try:
            user_obj = get_user_model().objects.get(id=user_id, is_verified=True)
        except ObjectDoesNotExist:
            return Response(
                {"code": 204, "message": get_message(204)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            UserNote.objects.create(user_id=user_obj, note_text=note_text)
            return Response({"code": 200, "message": get_message(200)})
        except Exception as e:
            logger.error(e)
            print(e)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        pk = self.kwargs.get("pk", None)
        user_id = request.user.get("user_id")
        note_text = request.data.get("note_text", None)
        try:
            get_user_model().objects.get(id=user_id, is_verified=True)
        except ObjectDoesNotExist as e:
            logger.error(e)
            return Response(
                {"code": 204, "message": get_message(204)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            user_note = UserNote.objects.get(pk=pk, user_id=user_id)
            user_note.note_text = note_text
            user_note.updated_at = timezone.now()
            user_note.is_edited = True
            user_note.save()
            return Response({"code": 200, "message": get_message(200)})
        except Exception as ex:
            logger.error(ex)
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def destroy(self, request, *args, **kwargs):
        user_id = request.user.get("user_id")
        try:
            get_user_model().objects.get(id=user_id, is_verified=True)
        except ObjectDoesNotExist as e:
            logger.error(e)
            return Response(
                {"code": 204, "message": get_message(204)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            UserNote.objects.get(pk=kwargs["pk"], user_id=user_id).delete()
            # super().destroy(request)
            return Response(
                {
                    "code": 200,
                    "message": get_message(200),
                }
            )

        except Exception:
            return Response(
                {"code": 114, "message": get_message(114)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
