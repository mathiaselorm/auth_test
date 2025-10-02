from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import CustomUser
from django.utils.translation import gettext_lazy as _


class CustomUserCreationForm(UserCreationForm):
    """
    A form for creating new users in the admin panel. Includes all required fields,
    plus repeated password fields for validation.
    """

    class Meta:
        model = CustomUser
        fields = (
            'first_name', 
            'last_name', 
            'email', 
            'phone_number', 
            'user_role', 
            'is_staff', 
            'is_active', 
        )
        labels = {
            'first_name': _('First Name'),
            'last_name': _('Last Name'),
            'email': _('Email Address'),
            'phone_number': _('Phone Number'),
            'user_role': _('User Role'),
            'is_active': _('Active'),
            'is_staff': _('Staff Status'),
        }


class CustomUserChangeForm(UserChangeForm):
    """
    A form for updating users in the admin panel. Excludes the password hash display field
    and provides a secure way to set a new password.
    """

    password = forms.CharField(
        label="Password",
        required=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text="Leave blank if you don't want to change the password.",
    )

    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'phone_number', 'user_role',
                  'is_active', 'is_staff', 'groups', 'user_permissions')

    def clean_password(self):
        """
        Validate the password field.
        """
        password = self.cleaned_data.get('password')
        if password:
            # Add any custom password validation here
            pass
        return password

    def save(self, commit=True):
        """
        Save the user, setting the password if provided.
        """
        user = super().save(commit=False)
        password = self.cleaned_data.get('password')
        if password:
            user.set_password(password)
        if commit:
            user.save()
            self.save_m2m()
        return user
