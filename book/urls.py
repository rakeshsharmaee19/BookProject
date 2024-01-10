from django.urls import path

from .views import RegisterUser, LoginView, LogoutView

urlpatterns = [
    path('registration/', RegisterUser.as_view({'post': 'create', 'put': 'update'})),
    # path('reset-password/', ResetPassword.as_view({'post': 'create', 'put': 'update'})),
    path('login/', LoginView.as_view()),
    path('logout/', LogoutView.as_view()),

]
