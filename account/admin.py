from django.contrib import admin
from django.contrib.auth.models import Group
from account.models import User, Profile
admin.site.unregister(Group)

class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'email', 'is_staff', 'is_superuser', 'is_active', 'last_login', 'joined_date']
    readonly_fields = ['password']
    list_editable = ['is_staff', 'is_superuser', 'is_active']
admin.site.register(User, UserAdmin)

class ProfileAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'image_tag', 'country', 'city', 'home_city', 'zip_code', 'phone', 'address', 'joined_date', 'updated_date']
admin.site.register(Profile, ProfileAdmin)