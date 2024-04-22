from django.contrib import admin

# Register your models here.
from user.models import (CustomUser, UserOtherDetails)

class CustomUserAdmin(admin.ModelAdmin):
    """Create CustomUser admin for display on admin panel"""

    list_display = ('id','username', 'email')

class UserOtherDetailsAdmin(admin.ModelAdmin):
    """Create UserOtherDetails admin for display on admin panel"""

    list_display = ('id', 'phone', 'address','otp')

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(UserOtherDetails, UserOtherDetailsAdmin)
