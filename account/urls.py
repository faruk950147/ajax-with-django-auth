from django.urls import path
from django.views.decorators.csrf import csrf_exempt, csrf_protect

from account.views import (
    SignUpView,
    SignInView,
    SignOutView,
    ChangesPasswordView,
    ProfileView,
    # Email verification view
    ActivationView,
    # View classes for validation
    SendOTPView,
    ResetPasswordView,
    UsernameValidationView, 
    EmailValidationView, 
    PasswordValidationView, 
    SignInValidationView,
)
urlpatterns = [
    # signup
    path('signup/', SignUpView.as_view(), name='signup'),
    # Email verification view
    path('activationview/<uidb64>/<token>/', ActivationView.as_view(), name='activationview'),
    path('sign/', SignInView.as_view(), name='sign'),
    path('signout/', SignOutView.as_view(), name='signout'),
    path('changespassword/', ChangesPasswordView.as_view(), name='changespassword'),
    path('sendotpview/', SendOTPView.as_view(), name='sendotpview'),
    path('resetpasswordview/', ResetPasswordView.as_view(), name='resetpasswordview'),
    path('profileview/', ProfileView.as_view(), name='profileview'),
    # Validation views for AJAX
    path('usernamevalidation/', csrf_exempt(UsernameValidationView.as_view()), name="usernamevalidation"),
    path('emailvalidation/', csrf_exempt(EmailValidationView.as_view()), name="emailvalidation"),
    path('passwordvalidation/', csrf_exempt(PasswordValidationView.as_view()), name="passwordvalidation"),
    path('signinvalidation/', csrf_exempt(SignInValidationView.as_view()), name="signinvalidation")
]
