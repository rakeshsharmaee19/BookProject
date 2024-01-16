from django.urls import path

from .views import RegisterUser, LoginView, LogoutView, UserSubscriberView, TicketView, ReviewView

urlpatterns = [
    path('registration/', RegisterUser.as_view({'post': 'create', 'put': 'update'}), name='register'),
    path('', LoginView.as_view(), name='user-login'),
    path('logout/', LogoutView.as_view()),

    path('subscribe/', UserSubscriberView.as_view({'post': 'create', 'delete': 'destroy'}), name='subscribe'),
    path('subscribe/<str:subscriber>/', UserSubscriberView.as_view({'get': 'list'}), name='subscribe-list'),

    path('ticket/', TicketView.as_view({'post': 'create'}), name='ticket'),
    path('ticket/<str:pk>/', TicketView.as_view({'put': 'update', 'delete': 'destroy', 'get': 'retrieve'}),
         name='ticket-update'),

    path('review/', ReviewView.as_view({'post': 'create'}), name='review'),

]
