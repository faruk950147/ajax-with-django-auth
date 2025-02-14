from django.forms import ValidationError
from django.views import generic
from django.urls import reverse_lazy
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import JsonResponse, HttpResponseRedirect
from django.db.models import Q
from django.core.mail import EmailMessage
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from validate_email import validate_email
from account.mixins import LogoutRequiredMixin
from account.utils import account_activation_token, EmailThread
from account.forms import SignUpForm, SignInForm, ChangePasswordForm, ResetPasswordForm, ResetPasswordConfirmForm
from account.models import Profile
import json
import random
User = get_user_model()


# Create your views here.
@method_decorator(never_cache, name='dispatch')
class UsernameValidationView(generic.View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            username = data.get('username', '').strip()

            if not isinstance(username, str) or not username.isalnum():
                return JsonResponse({'username_error': 'Username should only contain alphanumeric characters', 'status': 400})

            if User.objects.filter(username=username).exists():
                return JsonResponse({'username_error': 'Sorry, this username is already taken. Choose another one.', 'status': 400})

            return JsonResponse({'username_valid': True})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data', 'status': 400})

@method_decorator(never_cache, name='dispatch')
class EmailValidationView(generic.View):
    def post(self, request):    
        try:
            data = json.loads(request.body)
            email = data.get('email', '').strip()

            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({'email_error': 'Email is invalid', 'status': 400})

            if User.objects.filter(email__iexact=email).exists():
                return JsonResponse({'email_error': 'Sorry, this email is already in use. Choose another one.', 'status': 400})

            return JsonResponse({'email_valid': True})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data', 'status': 400})
        
@method_decorator(never_cache, name='dispatch')
class PasswordValidationView(generic.View):
    def post(self, request):    
        try:
            data = json.loads(request.body)
            password = data.get('password', '').strip()
            password2 = data.get('password2', '').strip()

            if password != password2:
                return JsonResponse({'password_error': 'Passwords do not match!', 'status': 400})

            if len(password) < 8:
                return JsonResponse({'password_info': 'Your password is too short! It must be at least 8 characters long.', 'status': 400})

            return JsonResponse({'password_valid': True})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data', 'status': 400})

@method_decorator(never_cache, name='dispatch')
class LoginUsernameValidationView(generic.View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            username = data.get('username', '').strip()

            if not User.objects.filter(Q(username__iexact=username) | Q(email__iexact=username)).exists():
                return JsonResponse({'username_error': 'No account found with this username or email. Please try again.', 'status': 400})

            return JsonResponse({'username_valid': True})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data', 'status': 400})
    
@method_decorator(never_cache, name='dispatch')
class SignUpView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/register.html')
    
    def post(self, request):
        if request.method == "POST" or request.method == "post" and request.is_ajax():
            try:
                username = request.POST.get('username', '').strip()
                email = request.POST.get('email', '').strip()
                password = request.POST.get('password', '').strip()

                user = User.objects.create_user(username=username, email=email, password=password)
                user.is_active = False
                user.save()

                # Sending activation email
                current_site = get_current_site(request)
                uid = urlsafe_base64_encode(force_bytes(user.id))
                token = account_activation_token.make_token(user)
                activation_url = f"http://{current_site.domain}{reverse_lazy('activation', kwargs={'uidb64': uid, 'token': token})}"

                email_subject = 'Just one more step - Verify your account'
                message = f"Hello {user.username},\n\nWe're happy you're joining us! Please verify your account using the link below:\n{activation_url}\n\nThanks,\nYour App Team"

                email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
                EmailThread(email_message).start()
                messages.success(request, 'Your account was registered successfully. Please check your email!')
                return JsonResponse({'status': 200})

            except Exception as e:
                messages.error(request, 'Something went wrong. Please try again.')
                return JsonResponse({'status': 400, 'error': str(e)})
        return render(request, 'account/register.html')

@method_decorator(never_cache, name='dispatch')    
class ActivationView(generic.View):
    def get(self, request, uidb64, token):
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = get_object_or_404(User, id=user_id)

            if not account_activation_token.check_token(user, token):
                messages.error(request, 'This token has already been used or is invalid.')
                return redirect('sign')

            user.is_active = True
            user.save()
            messages.success(request, 'Your account has been activated successfully!')
            return redirect('sign')

        except Exception as e:
            messages.error(request, 'Something went wrong. Please try again.')
            return redirect('sign')  

@method_decorator(never_cache, name='dispatch')
class SignInView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/login.html')

    def post(self, request):
        if request.method == "POST" or request.method == "post" and request.is_ajax():
            username_or_email = request.POST.get('username', '').strip()
            password = request.POST.get('password', '').strip()

            # Authenticate using either username or email
            user = User.objects.filter(Q(username__iexact=username_or_email) | Q(email__iexact=username_or_email)).first()
            if user:
                user = authenticate(request, username=user.username, password=password)

            if user:
                if user.is_superuser:
                    login(request, user)
                    messages.success(request, 'Admin login successful!')
                    return JsonResponse({'status': 200 })

                if user.is_active:
                    login(request, user)
                    messages.success(request, 'User login successful!')
                    return JsonResponse({'status': 201})
                
                return JsonResponse({'status': 403, 'messages': 'Your account is not active!'})

            return JsonResponse({'status': 400, 'messages': 'Invalid username/email or password!'})
        return render(request, 'account/login.html')
    
@method_decorator(never_cache, name='dispatch')    
class SignOutView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        if request.user.is_authenticated:
            logout(request)
            messages.success(request, 'You are logged out successfully !')
            return redirect('sign')
        else:
            messages.error(request, 'You are not logged in !')
            return redirect('sign')
    
    # def post(self, request):
    #     if request.method == "POST" or request.method == "post" and request.is_ajax():
    #         logout(request)
    #         messages.success(request, 'You are logged out successfully !')
    #         return JsonResponse({'status': 200})
    #     else:
    #         messages.error(request, 'Something went wrong')
    #         return JsonResponse({'status': 400})    
    #         html nav <button id="logout-btn">Logout</button> ajax call
    
@method_decorator(never_cache, name='dispatch')    
class ChangePasswordView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        return render(request, 'account/changes-password.html')
    def post(self, request):
        if request.user.is_authenticated:
            if request.method == "POST" or request.method == "post" and request.is_ajax():
                current_password = request.POST.get('current_password', '').strip()
                password = request.POST.get('password', '').strip()

                user = get_object_or_404(User, id=request.user.id) 
                # Check current password
                check_current_password = user.check_password(current_password)
                if check_current_password == True:
                    # Change password and update session
                    user.set_password(password)
                    user.save()
                    # Keeps the user logged in after password change
                    update_session_auth_hash(request, user)  
                    messages.success(request, 'Your password changes successfully !')
                    return JsonResponse({'status': 200, 'messages': 'Your password changes successfully !'})
                else:
                    messages.error(request, 'Your current password is incorrect!')
                    return JsonResponse({'status': 400, 'messages': 'Your current password is incorrect!'})
        else:
            messages.error(request, 'You are not logged in !')
            return redirect('sign')
        return render(request, 'account/changes-password.html')
    
@method_decorator(never_cache, name='dispatch')    
class ResetPasswordView(LogoutRequiredMixin, generic.View):
    def post(self, request):
        if request.method == "POST" or request.method == "post" and request.is_ajax():
            email = request.POST.get('email')
            try:
                if validate_email(email):
                    user = get_object_or_404(User, email=email)
                    otp = random.randint(100000, 999999)
                    email_subject = 'Reset to your password'
                    from_email = from_email = settings.EMAIL_HOST_USER
                    message = 'Hi '+user.username + f' Please otp below to reset your password \n{otp}'
                    email = EmailMessage(
                        email_subject,
                        message,
                        from_email,
                        [email]
                    )
                    EmailThread(email).start()
                    return JsonResponse({"status": 200, 'otp': otp, 'email': user.email, 'messages': 'Please check your email'})
            except Exception as e:
                    return JsonResponse({"status": 400, 'messages': str(e) + 'Invalid email'})
    
@method_decorator(never_cache, name='dispatch')    
class ForgotPasswordView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/reset-password.html')
    def post(self, request):
        if request.method == "POST" or request.method == "post" and request.is_ajax():
            email = request.POST.get('email')
            password = request.POST.get('password')
            user = get_object_or_404(User, email=email)
            user.set_password(password)
            user.save()
            if user.is_active:
                return JsonResponse({'status': 200, 'messages': 'Your password reset successfully !'})
            else:
                return JsonResponse({'status': 400,  'messages': 'Your account is not active'})
        return render(request, 'account/reset-password.html')

@method_decorator(never_cache, name='dispatch')    
class ProfileView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        return render(request, 'account/profile.html')
    def post(self, request):
        if request.user.is_authenticated:
            if request.method == "POST" or request.method == "post" or request.FILES and request.is_ajax():
                username = request.POST.get("username")
                email = request.POST.get("email")
                country = request.POST.get("country")
                city = request.POST.get("city")
                home_city = request.POST.get("home_city")
                zip_code = request.POST.get("zip_code")
                phone = request.POST.get("phone")
                address = request.POST.get("address")
                user = get_object_or_404(User, id=request.user.id)
                user.username = username
                user.email = email
                user.save()
                user_p = get_object_or_404(Profile, user=request.user.id)
                user_p.country = country
                user_p.city = city
                user_p.home_city = home_city
                user_p.zip_code = zip_code
                user_p.phone = phone
                user_p.address = address
                if "profile_image" in request.FILES:
                    profile_image = request.FILES.get("profile_image")
                    user_p.profile_image = profile_image
                user_p.save()
                return JsonResponse({"status": 200, 'messages': 'Your profile updated successfully!'})
        else:
            return JsonResponse({"status": 400, 'messages': 'Your are not authenticated'})
        return render(request, 'account/profile.html')