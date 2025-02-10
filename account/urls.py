from django.urls import path
from django.views.decorators.csrf import csrf_exempt, csrf_protect

from account.views import (
    SignUpView, ActivationView, SignInView, SignOutView, ChangePasswordView, ResetPasswordView, ForgotPasswordView,
    ProfileView, UsernameValidationView, EmailValidationView, PasswordValidationView, LoginUsernameValidationView
)
urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('activation/<uidb64>/<token>/', ActivationView.as_view(), name='activation'),
    path('sign/', SignInView.as_view(), name='sign'),
    path('signout/', SignOutView.as_view(), name='signout'),
    path('changepassword/', ChangePasswordView.as_view(), name='changepassword'),
    path('resetpassword/', ResetPasswordView.as_view(), name='resetpassword'),
    path('forgotpassword/', ForgotPasswordView.as_view(), name="forgotpassword"),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('usernamevalidation/', csrf_exempt(UsernameValidationView.as_view()), name="usernamevalidation"),
    path('emailvalidation/', csrf_exempt(EmailValidationView.as_view()), name="emailvalidation"),
    path('passwordvalidation/', csrf_exempt(PasswordValidationView.as_view()), name="passwordvalidation"),
    path('loginusernamevalidation/', csrf_exempt(LoginUsernameValidationView.as_view()), name="loginusernamevalidation")
]
