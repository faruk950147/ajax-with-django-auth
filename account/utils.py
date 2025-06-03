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
        self.email = email
        threading.Thread.__init__(self)
    def run(self):
        self.email.send(fail_silently=False)

def send_activation_email(user, request, email):
    current_site = get_current_site(request)
    uid = urlsafe_base64_encode(force_bytes(user.id))
    token = account_activation_token.make_token(user)
    scheme = 'https' if request.is_secure() else 'http'

    activation_url = f"{scheme}://{current_site.domain}{reverse_lazy('activationview', kwargs={'uidb64': uid, 'token': token})}"

    email_subject = 'Just one more step - Verify your account'
    message = f"Hello {user.username},\n\nWe're happy you're joining us! Please verify your account:\n{activation_url}\n\nThanks,\nYour App Team"

    email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
    EmailThread(email_message).start()
