from .views import CustomUserLoginView
from django.urls import path

from .views import ProfileUpdateView, ProfileDetailView
    # UserRegisterView, UserLoginView, UserPasswordChangeView, \
    # UserForgotPasswordView, UserPasswordResetConfirmView, UserConfirmEmailView, EmailConfirmationSentView, \
    # EmailConfirmedView, EmailConfirmationFailedView

urlpatterns = [
    path('user/edit/', ProfileUpdateView.as_view(), name='profile_edit'),
    path('user/<uuid:pk>/', ProfileDetailView.as_view(), name='profile_detail'),
    path('login/', CustomUserLoginView.as_view(), name='login')
    # path('password-change/', UserPasswordChangeView.as_view(), name='password_change'),
    # path('password-reset/', UserForgotPasswordView.as_view(), name='password_reset'),
    # path('set-new-password/<uidb64>/<token>/', UserPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # path('register/', UserRegisterView.as_view(), name='register'),
    # path('email-confirmation-sent/', EmailConfirmationSentView.as_view(), name='email_confirmation_sent'),
    # path('confirm-email/<str:uidb64>/<str:token>/', UserConfirmEmailView.as_view(), name='confirm_email'),
    # path('email-confirmed/', EmailConfirmedView.as_view(), name='email_confirmed'),
    # path('confirm-email-failed/', EmailConfirmationFailedView.as_view(), name='email_confirmation_failed'),
]

# urlpatterns = [
#     path('', CustomUserLoginView.as_view(), name='login'),
# ]