from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
import threading
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse_lazy
from django.core.mail import EmailMessage
from django.conf import settings
class AppTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (text_type(user.is_active) + text_type(user.id) + text_type(timestamp))
account_activation_token = AppTokenGenerator()

class EmailThread(threading.Thread):
    def __init__(self, email):
        threading.Thread.__init__(self)
        self.email = email

    def run(self):
        self.email.send(fail_silently=False)

class ActivationEmailSender:
    def __init__(self, user, request, email):
        self.user = user
        self.request = request
        self.email = email

    def build_activation_url(self):
        current_site = get_current_site(self.request)
        uid = urlsafe_base64_encode(force_bytes(self.user.id))
        token = account_activation_token.make_token(self.user)
        scheme = 'https' if self.request.is_secure() else 'http'
        return f"{scheme}://{current_site.domain}{reverse_lazy('activationview', kwargs={'uidb64': uid, 'token': token})}"

    def send(self):
        subject = 'Just one more step - Verify your account'
        activation_url = self.build_activation_url()
        message = (
            f"Hello {self.user.username},\n\n"
            f"We're happy you're joining us! Please verify your account:\n"
            f"{activation_url}\n\nThanks,\nYour App Team"
        )

        email_message = EmailMessage(subject, message, settings.EMAIL_HOST_USER, [self.email])
        EmailThread(email_message).start()

