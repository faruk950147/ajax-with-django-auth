from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
import threading

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