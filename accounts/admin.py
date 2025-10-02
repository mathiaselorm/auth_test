# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django import forms
from .models import CustomUser
from .forms import CustomUserCreationForm, CustomUserChangeForm

class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser

    list_display = ('id','email','first_name','last_name','phone_number','user_role','is_active','is_staff')
    list_display_links = ('id','email',)
    list_filter = ('is_active','is_staff','user_role')
    search_fields = ('email','first_name','last_name')
    ordering = ('-date_joined',)
    readonly_fields = ('date_joined','last_login','auth_version')

    fieldsets = (
        (None, {'fields': ('email','password')}),
        ('Personal info', {'fields': ('first_name','last_name','phone_number')}),
        ('Role & Status', {'fields': ('user_role','is_active','is_staff','is_superuser','groups','user_permissions')}),
        ('Important dates', {'fields': ('last_login','date_joined','auth_version')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email','password1','password2','first_name','last_name','phone_number','user_role','is_active','is_staff'),
        }),
    )


admin.site.register(CustomUser, CustomUserAdmin)
