from django.db import models
from django.http import HttpResponse
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.models import User
from django.utils.html import mark_safe

#account apps 
from account.managers import UserManager

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(
        max_length=150,
        validators=[UnicodeUsernameValidator, ],
        unique=True
    )
    email = models.EmailField(
        max_length=150,
        unique=True
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    joined_date = models.DateTimeField(auto_now_add=True)
    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", ]

    class Meta:
        ordering = ['-joined_date']
        verbose_name_plural = '1 User'
    
    def __str__(self):
        return f'{self.username}'

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profiles')
    profile_image = models.FileField(upload_to='profiles', null=True, blank=True)
    country = models.CharField(max_length=150, null=True, blank=True)
    city = models.CharField(max_length=150, null=True, blank=True)
    home_city = models.CharField(max_length=150, null=True, blank=True)
    zip_code = models.CharField(max_length=15, null=True, blank=True)
    phone = models.CharField(max_length=16, null=True, blank=True)
    address = models.TextField(max_length=500, null=True, blank=True)
    joined_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-joined_date']
        verbose_name_plural = '2 Profiles'
        
    @property
    def image_tag(self):   
        if self.profile_image:
            return mark_safe('<img src="%s" width="50" height="50"/>' % (self.profile_image.url))
        return mark_safe('<span>No Image</span>')  
        
    def __str__(self):
        return f"{self.user.username}'s Profile"   
         
    @receiver(post_save, sender=User)
    def Created_By_Profile(sender, instance, created, **kwargs):
        try:
            if created:
                #create profile
                profile = Profile.objects.create(user=instance)
                profile.save()
            else:
                return HttpResponse('Profile has mot created')
        except Exception as e:
            print(e)
            