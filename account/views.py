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
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import json
import random
User = get_user_model()
OTP_EXPIRATION_TIME = 300  # 5 minutes in seconds
from django.core.cache import cache

# Create your views here.
@method_decorator(never_cache, name='dispatch')
class UsernameValidationView(generic.View):
    def post(self, request):
        if request.method == "POST":
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
        if request.method == "POST":
            try:
                data = json.loads(request.body)
                email = data.get('email', '').strip()

                if not validate_email(email):
                    return JsonResponse({'email_error': 'Email is invalid', 'status': 400})
                    
                if User.objects.filter(email__iexact=email).exists():
                    return JsonResponse({'email_error': 'Sorry, this email is already in use. Choose another one.', 'status': 400})

                return JsonResponse({'email_valid': True})

            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON data', 'status': 400})
        
@method_decorator(never_cache, name='dispatch')
class PasswordValidationView(generic.View):
    def post(self, request):   
        if request.method == "POST": 
            try:
                data = json.loads(request.body)
                password = data.get('password', '').strip()
                password2 = data.get('password2', '').strip()

                if password != password2:
                    return JsonResponse({'password_error': 'Passwords does not match!', 'status': 400})

                if len(password) < 8:
                    return JsonResponse({'password_info': 'Your password is too short! It must be at least 8 characters long.', 'status': 400})

                return JsonResponse({'password_valid': True})

            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON data', 'status': 400})

@method_decorator(never_cache, name='dispatch')
class SignInValidationView(generic.View):
    def post(self, request):
        if request.method == "POST":
            try:
                data = json.loads(request.body)
                username = data.get('username', '').strip()

                if not User.objects.filter(Q(username__iexact=username) | Q(email__iexact=username)).exists():
                    return JsonResponse({'username_error': 'No account found with this username or email. Please try again.', 'status': 400})

                return JsonResponse({'username_valid': True})

            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON data', 'status': 400})
    
@method_decorator(never_cache, name='dispatch')
class ActivationView(generic.View):
    def get(self, request, uidb64, token):
        try:
            # get user id from uidb64
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = get_object_or_404(get_user_model(), id=user_id)

            # validate the token
            if not account_activation_token.check_token(user, token):
                messages.error(request, 'This token has already been used or is invalid.')
                return redirect('sign')

            # activate the user and login
            user.is_active = True
            user.save()
            messages.success(request, 'Your account has been activated successfully!')
            return redirect('home')  # Redirect to login page after activation

        except (TypeError, ValueError, OverflowError) as e:
            messages.error(request, 'The activation link is invalid or expired.')
            return redirect('sign')
        except Exception as e:
            logger.error(f"{e}")
            return redirect('sign')
            
@method_decorator(never_cache, name='dispatch')
class SignUpView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/register.html')

    def post(self, request):
        if request.method == "POST":  # Only handle AJAX requests
            try:
                # Parse the JSON data from request body
                data = json.loads(request.body)
                username = data.get('username', '').strip()
                email = data.get('email', '').strip()
                password = data.get('password', '').strip()
                password2 = data.get('password2', '').strip()

                if password != password2:
                    return JsonResponse({'status': 400, 'messages': 'Passwords do not match.'})

                # Validate password strength using Django's built-in validators
                # try:
                #     if not validate_password(password):
                #         return JsonResponse({'status': 400, 'messages': 'Password must be at least 8 characters long.'})
                # except ValidationError as e:
                #     return JsonResponse({'status': 400, 'messages': str(e.messages)})  

                # Create user
                user = User.objects.create_user(username=username, email=email, password=password)
                user.is_active = False
                user.save()

                # Sending activation email
                current_site = get_current_site(request)
                uid = urlsafe_base64_encode(force_bytes(user.id))
                token = account_activation_token.make_token(user)
                activation_url = f"http://{current_site.domain}{reverse_lazy('activationview', kwargs={'uidb64': uid, 'token': token})}"

                email_subject = 'Just one more step - Verify your account'
                message = f"Hello {user.username},\n\nWe're happy you're joining us! Please verify your account using the link below:\n{activation_url}\n\nThanks,\nYour App Team"

                email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
                EmailThread(email_message).start()
                
                return JsonResponse({'status': 200, 'messages': 'Your account was registered successfully. Please check your email!'})

            except json.JSONDecodeError:
                return JsonResponse({'status': 400, 'messages': 'Invalid JSON format!'})

            except Exception as e:
                return JsonResponse({'status': 400, 'messages': str(e)})

        return render(request, 'account/register.html')

@method_decorator(never_cache, name='dispatch')
class SignInView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/login.html')

    def post(self, request):
        if request.method == "POST":
            try:
                data = json.loads(request.body)
                username_or_email = data.get('username', '').strip()
                password = data.get('password', '').strip()

                # Authenticate using Django's built-in method
                user = authenticate(request, username=username_or_email, password=password)

                if user:
                    if not user.is_active:
                        return JsonResponse({'status': 403, 'messages': 'Your account is not active!'})

                    login(request, user)

                    if user.is_superuser:
                        messages.success(request, 'Admin login successful!')
                        return JsonResponse({'status': 200})

                    messages.success(request, 'User login successful!')
                    return JsonResponse({'status': 201})

                return JsonResponse({'status': 400, 'messages': 'Invalid username/email or password!'})

            except json.JSONDecodeError:
                return JsonResponse({'status': 400, 'messages': 'Invalid JSON format!'})

            except Exception as e:
                return JsonResponse({'status': 500, 'messages': f'Something went wrong: {str(e)}'})
        return render(request, 'account/login.html')

@method_decorator(never_cache, name='dispatch')    
class SignOutView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        logout(request)
        messages.success(request, 'You are sign out successfully!')
        return redirect('sign')
    
@method_decorator(never_cache, name='dispatch')
class ChangesPasswordView(LoginRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/changes-password.html')

    def post(self, request):
        if request.user.is_authenticated:
            if request.method == "POST":
                try:
                    data = json.loads(request.body)
                    current_password = data.get('current_password', '').strip()
                    password = data.get('password', '').strip()
                    password2 = data.get('password2', '').strip()
                    
                    if password != password2:
                        return JsonResponse({'status': 400, 'messages': 'Passwords do not match.'})

                    # Validate password strength using Django's built-in validators
                    # try:
                    #     if not validate_password(password):
                    #         return JsonResponse({'status': 400, 'messages': 'Password must be at least 8 characters long.'})
                    # except ValidationError as e:
                    #     return JsonResponse({'status': 400, 'messages': str(e.messages)})  

                    # Retrieve user
                    user = get_object_or_404(User, id=request.user.id)
                    # Check current password
                    check_current_password = user.check_password(current_password)
                    if check_current_password == True:
                        # Change password and update session
                        user.set_password(password)
                        user.save()
                        # Keeps the user logged in after password change
                        update_session_auth_hash(request, user)  
                        # messages.success(request, 'Your password changes successfully !')
                        return JsonResponse({'status': 200, 'messages': 'Your password changes successfully !'})
                    else:
                        # messages.error(request, 'Your current password is incorrect!')
                        return JsonResponse({'status': 400, 'messages': 'Your current password is incorrect!'})
                except json.JSONDecodeError:
                    return JsonResponse({'status': 400, 'messages': 'Invalid JSON format!'})

                except Exception as e:
                    return JsonResponse({'status': 500, 'messages': f'Something went wrong: {str(e)}'})
        else:
            return JsonResponse({'status': 400, 'messages': 'You are not logged in!'})
        return render(request, 'account/changes-password.html')
  
@method_decorator(never_cache, name='dispatch')    
class SendOTPView(LogoutRequiredMixin, generic.View):
    def post(self, request):
        if request.method == "POST":
            try:
                data = json.loads(request.body)
                email = data.get('email')
                if validate_email(email):
                    user = get_object_or_404(User, email=email)
                    otp = random.randint(100000, 999999)

                    # Store OTP with expiry in cache
                cache.set(f'otp_{email}', otp, timeout=OTP_EXPIRATION_TIME)

                email_subject = 'Reset Your Password'
                from_email = settings.EMAIL_HOST_USER
                message = f'Hi {user.username},\n\nPlease use the OTP below to reset your password:\n{otp}\n\nThis OTP is valid for 5 minutes only.'
                
                email_message = EmailMessage(
                    email_subject,
                    message,
                    from_email,
                    [email]
                )
                EmailThread(email_message).start()

                return JsonResponse({
                    "status": 200,
                    "messages": "OTP sent successfully!",
                    "email": user.email,
                    "otp": otp  # Return the OTP in the response
                })

            except Exception as e:
                return JsonResponse({"status": 400, "messages": f"Error: {str(e)}"})
        return JsonResponse({"status": 400, "messages": "Invalid request!"})

@method_decorator(never_cache, name='dispatch')    
class ResetPasswordView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/reset-password.html')
    
    def post(self, request):
        if request.method == "POST":
            try:
                data = json.loads(request.body)
                print(data)
                email = data.get('email')
                otp = data.get('otp')
                password = data.get('password')
                print(otp)

                # Retrieve OTP from cache
                cached_otp = cache.get(f'otp_{email}')
                print("cached_otp: ", cached_otp)

                if cached_otp is None:
                    return JsonResponse({'status': 400, 'messages': 'OTP expired or invalid!'})

                if str(otp) != str(cached_otp):
                    print("str(otp): ", str(otp), "str(cached_otp): ", str(cached_otp))
                    return JsonResponse({'status': 400, 'messages': 'Invalid OTP!'})

                user = get_object_or_404(User, email=email)
                user.set_password(password)
                user.save()

                # Remove OTP from cache after successful reset
                cache.delete(f'otp_{email}')

                return JsonResponse({'status': 200, 'messages': 'Your password has been reset successfully!'})

            except Exception as e:
                return JsonResponse({'status': 400, 'messages': f"Error: {str(e)}"})

            return JsonResponse({"status": 400, "messages": "Invalid request!"})
        
@method_decorator(never_cache, name='dispatch')    
class ProfileView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        
        return render(request, 'account/profile.html')
    def post(self, request):
        if request.user.is_authenticated:
            if request.method == "POST":
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