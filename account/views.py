from django.views import generic
from django.urls import reverse_lazy
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import authenticate, login, logout
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
        data = json.loads(request.body)
        username = data.get('username')
        if not str(username).isalnum():
            return JsonResponse({'username_error': 'Username should only contain alphanumeric characters'})
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'Sorry username in used,choose another one'})
        return JsonResponse({'username_valid': True})

@method_decorator(never_cache, name='dispatch')
class EmailValidationView(generic.View):
    def post(self, request):    
        data = json.loads(request.body)
        email = data.get('email')
        if not validate_email(email):
            return JsonResponse({'email_error': 'Email is invalid'})
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'Sorry email in used,choose another one '})
        return JsonResponse({'email_valid': True})
        
@method_decorator(never_cache, name='dispatch')
class PasswordValidationView(generic.View):
    def post(self, request):    
        data = json.loads(request.body)
        password = data.get('password')
        password2 = data.get('password2')
        
        if password != password2:
            return JsonResponse({'password_error': 'Your password do not matches !'})
        if len(password) and len(password2) < 8:
            return JsonResponse({'password_info': 'Your password too shorts !'})
        return JsonResponse({'password_valid': True})

@method_decorator(never_cache, name='dispatch')
class LoginUsernameValidationView(generic.View):
    def post(self, request):
        data = json.loads(request.body)
        username = data.get('username')
        if not User.objects.filter(Q(username__iexact=username) | Q(email__iexact=username)).exists():
            return JsonResponse({'username_error': 'Sorry there is no account with this username or this email, choose another one !'})
        return JsonResponse({'username_valid': True})
    
@method_decorator(never_cache, name='dispatch')
class SignUpView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/register.html')
    
    def post(self, request):
        if request.method == "POST" or request.method == "post" and request.is_ajax():
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            user = User.objects.create_user(username=username, email=email, password=password)
            user.set_password(password)
            user.is_active = False
            user.save()
            try:    
                current_site = get_current_site(request)
                email_body = {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.id)),
                'token': account_activation_token.make_token(user),
                }
                link = reverse_lazy('activation', kwargs={
                    'uidb64': email_body['uid'], 'token': email_body['token']               
                })
                activation_url = 'http://'+current_site.domain+link
                email_subject = 'Just one more thing - please verify your account'
                from_email = from_email = settings.EMAIL_HOST_USER
                message = 'Hello \n'+user.username + " We're happy you're taking the next step to see how your app scales. Simply verify your account below and you are on your way to testing and improving your web app!Verify your account :"+activation_url+"\n Thanks "+user.username
                email = EmailMessage(
                    email_subject,
                    message,
                    from_email,
                    [email]
                )
                EmailThread(email).start()
                messages.success(request, 'Your account register successfully !')
                return JsonResponse({'status': 200})
            except Exception as e:
                return JsonResponse({'status': 400})
        return render(request, 'account/register.html')

@method_decorator(never_cache, name='dispatch')    
class ActivationView(generic.View):
    def get(self, request, uidb64, token):
        try:
            id = force_str(urlsafe_base64_decode(uidb64))
            user = get_object_or_404(User, id=id)
            if not account_activation_token.check_token(user, token):
                messages.error(request, 'This token already used or invalid')
                return redirect('sign')
            user.is_active = True
            user.save()
            messages.success(request, 'Your account activated successfully !')
            return redirect('sign')
        except Exception as e:
            messages.error(request, 'Something went wrong')
        return redirect('sign')   

@method_decorator(never_cache, name='dispatch')
class SignInView(LogoutRequiredMixin, generic.View):
    def get(self, request):
        return render(request, 'account/login.html')
    
    def post(self, request):
        if request.method == "POST" or request.method == "post" and request.is_ajax():
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)   
            if user:
                if user.is_superuser:
                    login(request, user)
                    messages.success(request, 'You are admin logged in successfully !')
                    return JsonResponse({'status': 200})                    
                if user.is_active:
                    login(request, user)
                    messages.success(request, 'You are user logged in successfully !')
                    return JsonResponse({'status': 201})
                else:
                    messages.error(request, 'Your account is not active')
                    return JsonResponse({'status': 202})
            else:
                messages.error(request, 'Invalid username or password')
                return JsonResponse({'status': 400})
        return render(request, 'account/login.html')
    
@method_decorator(never_cache, name='dispatch')    
class SignOutView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        logout(request)
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
        if request.method == "POST" or request.method == "post" and request.is_ajax():
            current_password = request.POST.get('current_password')
            password = request.POST.get('password')
            user = get_object_or_404(User, id=request.user.id)     
            check_current_password = user.check_password(current_password)
            if check_current_password == True:
                user.set_password(password)
                user.save()
                messages.success(request, 'Your password changes successfully !')
                return JsonResponse({'status': 200})
            else:
                messages.error(request, 'Your current password is wrong !')
                return JsonResponse({'status': 400})
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
                    messages.success(request, 'We have sent you an email with otp to reset your password')
                    return JsonResponse({"status": 200, 'otp': otp, 'email': user.email})
            except Exception as e:
                messages.error(request, 'Something went wrong')
                return JsonResponse({"status": 400})
    
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
                messages.success(request, 'Your password reset successfully !')
                return JsonResponse({'status': 200})
        return render(request, 'account/reset-password.html')

@method_decorator(never_cache, name='dispatch')    
class ProfileView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        return render(request, 'account/profile.html')
    def post(self, request):
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
            messages.success(request, 'Your profile edited successfully !')
            return JsonResponse({"status": 200})
        return render(request, 'account/profile.html')