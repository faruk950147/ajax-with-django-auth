import threading
from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()


""" 
SignUp form
"""
class SignUpForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({'class': 'form-control'})
            
    password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput(attrs={'placeholder': 'Password'})
    )
    password2 = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'})
    )

    class Meta:
        model = User
        fields = (
            'username', 'email', 'password', 'password2',
        )
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Username'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Email'}),
        }
        
""" 
SignIn form
"""
class SignInForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({'class': 'form-control'})

    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={'placeholder': 'Username or Email'})
    )
    password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput(attrs={'placeholder': 'Password'})
    )
    
""" 
Reset password form
"""    
class ResetPasswordForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})

    email = forms.EmailField(
        max_length=150,
        widget=forms.EmailInput(attrs={'placeholder': 'Email'})
    )

""" 
Reset password confirm form
"""
 
class ResetPasswordConfirmForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})

    password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput(attrs={'placeholder': 'New Password'})
    )
    password2 = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'})
    )

""" 
Change password confirm form
"""     
class ChangePasswordForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({"class": "form-control"})
    
    current_password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput({'placeholder': 'Current Password'})
    )
    password = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput({'placeholder': 'New Password'})
    )
    password2 = forms.CharField(
        max_length=150,
        widget=forms.PasswordInput({'placeholder': 'Confirm Password'})
    )