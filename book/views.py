import sys

from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render, redirect
from rest_framework import viewsets, status
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from django.contrib.auth import get_user_model, authenticate, logout
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.pagination import PageNumberPagination

from .models import UserFollows, Ticket, Review
from .serializers import RegistrationSerializer, LoginSerializer, SubscriberSerializer, TicketSerializer, \
    ReviewSerializer
from utils import response_on_exception
from .forms import UserLoginForm, UserRegistrationForm


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 10


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
    permission_classes = (AllowAny,)

    def create(self, request, *args, **kwargs):
        """
        Endpoint for create user
        """
        try:
            validated_data = request.data
            print(validated_data)
            validated_data['first_name'] = validated_data["username"]
            validated_data['last_name'] = ""
            try:
                get_user_model().objects.get(username=validated_data['username'], is_active=True)
                return JsonResponse({'success': False, 'message': 'User already exist'},
                                    status=status.HTTP_400_BAD_REQUEST)
            except ObjectDoesNotExist:
                serializer = self.serializer_class(data=validated_data)
                if serializer.is_valid():
                    serializer.save()
                    # return redirect('login')
                    return JsonResponse({'success': True, 'message': 'User Created successfully.'},
                                        status=status.HTTP_201_CREATED)
                else:
                    return JsonResponse(
                        {'success': False, 'message': 'Please provide valid data.', 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def get(self, request, *args, **kwargs):
        # HTML-based registration
        print("dfjnbj")
        form = UserRegistrationForm()
        print(1)
        print(form.data)
        return render(request, 'book/register.html', {'form': form})

    def post(self, request, *args, **kwargs):
        # HTML-based registration form submission
        form = UserRegistrationForm(request.POST)
        print("vsdvs")
        if form.is_valid():
            user = form.save()
            return redirect('')
        return render(request, 'book/register.html', {'form': form})


class LoginView(APIView):
    serializer_class = LoginSerializer
    authentication_classes = (CsrfExemptSessionAuthentication,)

    def post(self, request):
        """
        Endpoint for user login
        """
        try:
            username = request.data.get("username")
            password = request.data.get("password")
            try:
                get_user_model().objects.get(username=username, is_active=True)
            except ObjectDoesNotExist:
                return JsonResponse({'message': 'User dose not exist!'}, status=status.HTTP_400_BAD_REQUEST)
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    serializer = self.serializer_class(user)
                    token = Token.objects.get_or_create(user=user)
                    return JsonResponse({
                        'success': True,
                        'message': "User Login Successfully",
                        "data": {
                            "token": token[0].key,
                            "user": serializer.data
                        }
                    }, status=status.HTTP_200_OK)
                else:
                    return JsonResponse({'message': 'Account is pending for activation'},
                                        status=status.HTTP_200_OK)
            return JsonResponse({'message': 'Invalid credentials!'},
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def get(self, request, *args, **kwargs):
        # HTML-based login
        form = UserLoginForm()
        return render(request, 'book/login.html', {'form': form})

    def post(self, request, *args, **kwargs):
        # HTML-based login form submission
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user = authenticate(request, username=username, password=password)

            if user:
                # login(request, user)
                return redirect('subscribe/subscriber/')
            else:
                return render(request, 'book/login.html', {'form': form, 'error': 'Invalid credentials'})
        return render(request, 'book/login.html', {'form': form})


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


class UserSubscriberView(viewsets.ModelViewSet):
    queryset = UserFollows.objects.all()
    serializer_class = SubscriberSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, TokenAuthentication)
    permission_classes = (IsAuthenticated, )
    pagination_class = StandardResultsSetPagination

    def list(self, request, subscriber):
        try:
            if subscriber.upper() == 'SUBSCRIBER':
                dataset = self.queryset.filter(user=request.user).order_by('-created_date')
            else:
                dataset = self.queryset.filter(followed_user=self.request.user).order_by('-created_date')
            page = self.paginate_queryset(dataset)
            serializer = self.serializer_class(page, many=True)
            if serializer.data:
                return JsonResponse(serializer.data, status=status.HTTP_200_OK)
                # return self.get_paginated_response(serializer.data)
            else:
                context = {
                    "success": False,
                    "message": "You have not subscribed to any subscribers."
                }
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def create(self, request):
        try:
            request_data = request.data
            context = {
                "success": True,
                "message": "Data added successfully"
            }

            if request_data.get("followed_user"):
                if request.user.username == request_data.get("followed_user"):
                    return JsonResponse({
                        "success": False,
                        "message": "You can not follow yourself."
                    }, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    followed_user = get_user_model().objects.get(username=request_data.get("followed_user"))
                except ObjectDoesNotExist:
                    context["success"] = False
                    context["message"] = "User dose not exists."
                    return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
            else:
                context["success"] = False
                context["message"] = "Please Provide correct username"
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
            UserFollows.objects.create(followed_user=followed_user, user=request.user)

            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def destroy(self, request):
        try:
            request_data = request.data
            if request_data.get("followed_user"):
                self.queryset.get(user=request.user, followed_user=request_data.get("followed_user")).delete()
            context = {
                "success": True,
                "message": "User unsubscribe successfully"
            }
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())


class TicketView(viewsets.ModelViewSet):
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, TokenAuthentication)
    permission_classes = (IsAuthenticated,)
    pagination_class = StandardResultsSetPagination

    def retrieve(self, request, *args, **kwargs):
        try:
            queryset = self.get_object()
            serializer = self.get_serializer(queryset)
            data = serializer.data
            data["id"] = queryset.id
            return JsonResponse({
                "success": True,
                "data": data,
                "message": "Ticket retrieved successfully"
            }, json_dumps_params={'indent': 2}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            context = {
                "success": False,
                "message": "Ticket does not exist"
            }
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def create(self, request, *args, **kwargs):
        try:
            validated_data = request.data
            serializer = self.get_serializer(data=validated_data)
            context = {
                "success": False,
                "message": "Unable to create ticket"
            }
            if serializer.is_valid(raise_exception=True):
                serializer.save(user=request.user)
                context["success"] = True
                context["message"] = "Ticket has created successfully."
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_201_CREATED)
            else:
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def update(self, request, *args, **kwargs):
        try:
            context = {
                "success": False,
                "message": "Unable to update Ticket"
            }
            dataset = self.get_object()
            validated_data = request.data
            serializer = self.get_serializer(dataset, data=validated_data)
            if serializer.is_valid(raise_exception=True):
                serializer.save(created_by=request.user.username)
                context["success"] = True
                context["message"] = "Ticket has updated successfully."
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_200_OK)
            else:
                context["error"] = serializer.errors
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            context["message"] = "Ticket dose not exists."
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def destroy(self, request, *args, **kwargs):
        try:
            context = {
                "success": False,
                "message": "Ticket dose not exists."
            }
            dataset = self.get_object()
            dataset.delete()
            context["success"] = True
            context["message"] = "Ticket has been deleted successfully."
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_204_NO_CONTENT)
        except ObjectDoesNotExist:
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())


class ReviewView(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, TokenAuthentication)
    permission_classes = (IsAuthenticated,)
    pagination_class = StandardResultsSetPagination

    def create(self, request, *args, **kwargs):
        try:
            validated_data = request.data
            ticket = validated_data.get("ticket")
            ticket_object = Ticket.objects.get(id=ticket)
            serializer = self.get_serializer(data=validated_data)
            context = {
                "success": False,
                "message": "Unable to create Review"
            }
            if serializer.is_valid(raise_exception=True):
                serializer.save(user=request.user, ticket=ticket_object)
                context["success"] = True
                context["message"] = "Review has created successfully."
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_201_CREATED)
            else:
                context["error"] = serializer.errors
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def update(self, request, *args, **kwargs):
        try:
            context = {
                "success": False,
                "message": "Unable to update Ticket"
            }
            dataset = self.get_object()
            validated_data = request.data
            serializer = self.get_serializer(dataset, data=validated_data)
            if serializer.is_valid(raise_exception=True):
                serializer.save(created_by=request.user.username)
                context["success"] = True
                context["message"] = "Review has updated successfully."
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_200_OK)
            else:
                context["error"] = serializer.errors
                return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            context["message"] = "Review dose not exists."
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())

    def destroy(self, request, *args, **kwargs):
        try:
            context = {
                "success": False,
                "message": "review dose not exists."
            }
            dataset = self.get_object()
            dataset.delete()
            context["success"] = True
            context["message"] = "Review has been deleted successfully."
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_204_NO_CONTENT)
        except ObjectDoesNotExist:
            return JsonResponse(context, json_dumps_params={'indent': 2}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return response_on_exception(e, sys.exc_info())
