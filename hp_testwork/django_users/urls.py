from django.urls import path
from .views import (
    MainView,
    UserLoginView,
    UserLogoutView,
    UserRegisterView,
    UsersListView,
    UserEditView,
    UserDetailView,
    UserPasswordChangeView,
    UserForgotPasswordView,
    UserPasswordResetConfirmView,
    EmailConfirmationSentView,
    EmailConfirmedView,
    EmailConfirmationFailedView,
    UserConfirmEmailView
)


urlpatterns = [
    path('', MainView.as_view(), name='main'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('register/', UserRegisterView.as_view(), name='register'),
    path('users_list/', UsersListView.as_view(), name='user_list'),
    path('user_edit/', UserEditView.as_view(), name='user_edit'),
    path('user/<uuid:pk>/', UserDetailView.as_view(), name='user_detail'),
    path('<uuid:pk>/password/', UserPasswordChangeView.as_view(), name='password_change'),
    path('password-reset/', UserForgotPasswordView.as_view(), name='password_reset'),
    path('set-new-password/<str:uidb64>/<str:token>/', UserPasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('email-confirmation-sent/', EmailConfirmationSentView.as_view(), name='email_confirmation_sent'),
    path('confirm-email/<str:uidb64>/<str:token>/', UserConfirmEmailView.as_view(), name='confirm_email'),
    path('email-confirmed/', EmailConfirmedView.as_view(), name='email_confirmed'),
    path('confirm-email-failed/', EmailConfirmationFailedView.as_view(), name='email_confirmation_failed'),
]
