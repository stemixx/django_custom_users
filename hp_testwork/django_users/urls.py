from .views import MainView, CustomLogoutView, UsersListView, UserEditView, UserDetailView, UserRegisterView, CustomUserLoginView
from django.urls import path

# from .views import ProfileUpdateView, ProfileDetailView, \
#     UserRegisterView#, UserLoginView, UserPasswordChangeView, \
    # UserForgotPasswordView, UserPasswordResetConfirmView, UserConfirmEmailView, EmailConfirmationSentView, \
    # EmailConfirmedView, EmailConfirmationFailedView

urlpatterns = [
    path('', MainView.as_view(), name='main'),
    path('login/', CustomUserLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('register/', UserRegisterView.as_view(), name='register'),
    path('users_list/', UsersListView.as_view(), name='user_list'),
    path('user_edit/', UserEditView.as_view(), name='user_edit'),
    path('user/<uuid:pk>/', UserDetailView.as_view(), name='user_detail'),

    # path('password-change/', UserPasswordChangeView.as_view(), name='password_change'),
    # path('password-reset/', UserForgotPasswordView.as_view(), name='password_reset'),
    # path('set-new-password/<uidb64>/<token>/', UserPasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    # path('email-confirmation-sent/', EmailConfirmationSentView.as_view(), name='email_confirmation_sent'),
    # path('confirm-email/<str:uidb64>/<str:token>/', UserConfirmEmailView.as_view(), name='confirm_email'),
    # path('email-confirmed/', EmailConfirmedView.as_view(), name='email_confirmed'),
    # path('confirm-email-failed/', EmailConfirmationFailedView.as_view(), name='email_confirmation_failed'),
]

# urlpatterns = [
#     path('', CustomUserLoginView.as_view(), name='login'),
# ]
