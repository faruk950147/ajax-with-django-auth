from django.contrib import admin
from unfold.admin import ModelAdmin
from django.contrib.auth.models import Group
from account.models import User, Profile
admin.site.unregister(Group)

class UserAdmin(ModelAdmin):
    list_display = ['id', 'username', 'email', 'is_staff', 'is_superuser', 'is_active', 'last_login', 'joined_date']
    list_editable = ['is_staff', 'is_superuser', 'is_active']
    search_fields = ['username', 'email']
    readonly_fields = ['password']
admin.site.register(User, UserAdmin)

class ProfileAdmin(ModelAdmin):
    list_display = ['id', 'user', 'image_tag', 'country', 'city', 'zip_code', 'phone', 'joined_date', 'updated_date']
    search_fields = ['user__username', 'phone', 'city', 'country']
    list_filter = ['country', 'city', 'joined_date']
    readonly_fields = ['image_tag']
admin.site.register(Profile, ProfileAdmin)