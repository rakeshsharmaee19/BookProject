import sys

from django.core.exceptions import ObjectDoesNotExist
from rest_framework import viewsets, status
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token

from ..serializers import RegistrationSerializer
from bookReview.utils import response_on_exception


# Create your views here.
class CsrfExemptSessionAuthentication(SessionAuthentication):
    """
    Session authentication class without csrf protection.
    """

    def enforce_csrf(self, request):
        """
        Disable csrf protection.
        """
        return


class RegisterUser(viewsets.ModelViewSet):
    """
        View For user Registration
    """
    queryset = get_user_model().objects.all()
    serializer_class = RegistrationSerializer
    authentication_classes = (CsrfExemptSessionAuthentication,)

    def create(self, request, *args, **kwargs):
        """
        Endpoint for create user
        """
        try:
            validated_data = request.data
            validated_data['username'] = validated_data['email']
            try:
                get_user_model().objects.get(email=validated_data['email'], is_active=True)
                return JsonResponse({'success': False, 'message': 'Email already exist'},
                                    status=status.HTTP_400_BAD_REQUEST)
            except:
                serializer = self.serializer_class(data=validated_data)
                if serializer.is_valid():
                    serializer.save(created_by=validated_data['email'])
                    return JsonResponse({'success': True, 'message': 'OTP sent successfully'},
                                        status=status.HTTP_201_CREATED)
                else:
                    return JsonResponse(
                        {'success': False, 'message': 'Please provide valid data.', 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def update(self, request, *args, **kwargs):
        """
        Endpoint for activate user
        """
        try:
            email = request.data.get('email')
            otp = request.data.get('otp')
            if not email or not otp:
                return JsonResponse({'message': 'Email and OTP are required.', 'success': False},
                                    status=status.HTTP_400_BAD_REQUEST)
            try:
                # Retrieve the User and UserOTP objects from the database
                user = get_user_model().objects.get(email=email)
                # user_otp = OTP.objects.get(user=user, otp=otp, otp_type='register')
            except ObjectDoesNotExist:
                return JsonResponse({'message': 'Invalid OTP!', 'success': False},
                                    status=status.HTTP_400_BAD_REQUEST)
            user.is_active = True
            user.is_email_verified = True
            user.save()
            # user_otp.delete()
            return JsonResponse({'message': 'Your account has been activated.', 'success': True},
                                status=status.HTTP_200_OK)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())


class LoginView(APIView):
    authentication_classes = (CsrfExemptSessionAuthentication,)

    def post(self, request):
        """
        Endpoint for user login
        """
        try:
            email = request.data.get("email")
            password = request.data.get("password")
            try:
                user_object = get_user_model().objects.get(email=email, is_active=True)
                if not user_object.approved:
                    return JsonResponse({'message': 'Account is pending for approval from Neoma Investor Team'},
                                        status=status.HTTP_200_OK)

            except ObjectDoesNotExist:
                return JsonResponse({'message': 'Email dose not exist!'}, status=status.HTTP_400_BAD_REQUEST)
            user = authenticate(username=email, password=password)
            if user is not None:
                token = Token.objects.get_or_create(user=user)
                return JsonResponse({
                    'success': True,
                    'message': "User Login Successfully",
                    "data": {
                        "token": token[0].key
                    }
                },
                    status=status.HTTP_200_OK)
            return JsonResponse({'message': 'Invalid credentials!'},
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())


class LogoutView(APIView):
    """
    Class to view logout.
    """
    authentication_classes = (CsrfExemptSessionAuthentication, TokenAuthentication)

    @staticmethod
    def get(request):
        """
        Endpoint for user logout.
        """
        try:
            logout(request)
            key = request.auth.key
            Token.objects.filter(key=key).delete()
            return JsonResponse({'message': 'Your account has been logout successfully.', 'success': True},
                                status=status.HTTP_200_OK)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())
