from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.contrib.auth import password_validation
import logging
from datetime import timedelta
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils.crypto import get_random_string
from django_rest_passwordreset.signals import reset_password_token_created
from django_rest_passwordreset.models import ResetPasswordToken

from .models import UserRole

logger = logging.getLogger(__name__)

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the user model.
    """
    user_role = serializers.CharField(label=_("User Role"), required=False)

    class Meta:
        model = User
        fields = (
            'id', 'first_name', 'last_name', 'email', 
            'phone_number', 'date_joined', 'last_login', 'user_role'
        )
        read_only_fields = ('id', 'date_joined', 'last_login')
        extra_kwargs = {
            'first_name': {'label': _("First Name")},
            'last_name': {'label': _("Last Name")},
            'phone_number': {'label': _("Phone Number")},
            'email': {'label': _("Email Address")}
        }
    
    def validate_email(self, value):
        norm = value.lower()
        if self.instance:
            if User.objects.filter(email__iexact=norm).exclude(id=self.instance.id).exists():
                raise ValidationError(_("This email is already in use by another account."))
        else:
            if User.objects.filter(email__iexact=norm).exists():
                raise ValidationError(_("This email is already in use by another account."))
        return norm

    def update(self, instance, validated_data):
        """
        Update and return an existing `User` instance, given the validated data.
        Excludes changes to superuser status and sensitive fields.
        """
        # Define uneditable fields
        uneditable_fields = {'password', 'is_superuser', 'user_role'}
        validated_data = {k: v for k, v in validated_data.items() if k not in uneditable_fields}

        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Log updates
        updated_fields = ', '.join(validated_data.keys())
        logger.info(f"User {instance.email} updated fields: {updated_fields} successfully.")

        return instance
    
class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    """
    user_role = serializers.CharField(label=_("User Role"))

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'phone_number', 'user_role')

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise ValidationError(_("This email is already in use."))
        return value.lower()

    def validate_user_role(self, value):
        # Normalize to lowercase for storing the role code
        normalized = value.strip().lower()  # e.g., 'admin' remains 'admin'
        valid_codes = [code for code, _ in UserRole.choices]
        if normalized and normalized not in valid_codes:
            raise ValidationError(_(
                f"Invalid role '{value}'. Must be one of: {', '.join(valid_codes)}"
            ))
        return normalized

    def validate(self, data):
        request_user = self.context['request'].user

        if request_user.is_authenticated and request_user.user_role == UserRole.MANAGER:
            # Manager cannot create Admin accounts
            if data.get('user_role') in [UserRole.ADMIN]:
                raise ValidationError({"user_role": _("You do not have permission to create accounts with this role.")})
        return data


    def create(self, validated_data):
        user_role_value = validated_data.pop('user_role')
        validated_data['user_role'] = user_role_value

        # Generate a random default password
        default_password = get_random_string(length=8)

        # Create the user with the generated password
        user = User.objects.create_user(**validated_data)
        user.set_password(default_password)
        user.save()
        logger.info(f"User created successfully: {user.get_full_name()}")

        # Trigger the password reset process
        token = ResetPasswordToken.objects.create(
            user=user,
            user_agent=self.context['request'].META.get('HTTP_USER_AGENT', ''),
            ip_address=self.context['request'].META.get('REMOTE_ADDR', ''),
        )

        # Send the password reset token via signal
        reset_password_token_created.send(
            sender=self.__class__,
            instance=self,
            reset_password_token=token,
            created_via='registration'
        )

        return user


class PublicUserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for public user registration.
    Allows users to select their role or defaults to Supervisor.
    """
    password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        label=_("Password")
    )
    password_confirm = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        label=_("Confirm Password")
    )
    user_role = serializers.ChoiceField(
        choices=UserRole.choices,
        required=False,
        allow_blank=True,
        label=_("User Role"),
        help_text=_("Select your role. Defaults to Supervisor if not specified.")
    )

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'phone_number', 'user_role', 'password', 'password_confirm')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
            'user_role': {'required': False},
        }

    def validate_email(self, value):
        """Validate email uniqueness"""
        normalized_email = value.lower().strip()
        if User.objects.filter(email__iexact=normalized_email).exists():
            raise serializers.ValidationError(_("A user with this email already exists."))
        return normalized_email

    def validate_user_role(self, value):
        """Validate user role selection for public registration"""
        if not value:
            # If no role specified, return None (will default to Supervisor)
            return None
            
        # Normalize the role value
        normalized = value.strip().lower()
        
        # Check if it's a valid role
        valid_codes = [code for code, _ in UserRole.choices]
        if normalized not in valid_codes:
            raise serializers.ValidationError(_(
                f"Invalid role '{value}'. Available options: {', '.join([label for code, label in UserRole.choices])}"
            ))
        
        # Security: Prevent public users from creating Admin accounts
        # Users can select Manager or Supervisor roles only
        if normalized == UserRole.ADMIN:
            raise serializers.ValidationError(_(
                "Admin role cannot be selected during public registration. Please contact an administrator."
            ))
        
        return normalized

    def validate(self, data):
        """Validate password confirmation and role constraints"""
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({
                "password_confirm": _("Password and confirmation do not match.")
            })
        
        # Validate password strength using Django's validators
        password_validation.validate_password(data['password'])
        
        # Set default role if none specified
        if not data.get('user_role'):
            data['user_role'] = UserRole.SUPERVISOR
            
        return data

    def create(self, validated_data):
        """Create a new public user with selected or default role"""
        # Remove password_confirm from validated_data
        password = validated_data.pop('password')
        validated_data.pop('password_confirm', None)
        
        # Ensure user_role is set (should be from validation, but extra safety)
        if not validated_data.get('user_role'):
            validated_data['user_role'] = UserRole.SUPERVISOR
        
        # Use the specialized public user creation method
        user = User.objects.create_public_user(password=password, **validated_data)
        
        logger.info(f"Public user registered: {user.get_full_name()} ({user.email}) with role: {user.user_role}")
        return user
    
   
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Allows the inclusion of a 'remember_me' flag in the token request
    and extends the token lifetime if set.
    """
    remember_me = serializers.BooleanField(required=False, default=False)
    
    # Expose created tokens on the instance (not in the HTTP response)
    refresh_token_obj = None
    access_token_obj = None
    remember_me_bool = False

    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user
        remember_me = bool(self.initial_data.get('remember_me', False))
        self.remember_me_bool = remember_me

        refresh_token_obj = self.get_token(user)
        # Persist the policy on the token itself
        refresh_token_obj['remember_me'] = remember_me
        refresh_token_obj['av'] = user.auth_version

        if remember_me:
            # Extend refresh token (keeps your existing 5-day behavior)
            refresh_token_obj.set_exp(lifetime=timedelta(days=5))

        access_token_obj = refresh_token_obj.access_token
        access_token_obj['av'] = user.auth_version

        # Store for the view to use (no body leakage)
        self.refresh_token_obj = refresh_token_obj
        self.access_token_obj = access_token_obj

        # Do NOT include tokens in the response body
        data.pop('refresh', None)
        data.pop('access', None)
        return data


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for changing a user's password, requiring the old password for verification.
    """
    old_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        label=_("Old Password")
    )
    new_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        label=_("New Password")
    )

    def validate(self, data):
        user = self.context['request'].user

        # Check if the old password is correct
        if not user.check_password(data['old_password']):
            raise ValidationError({"old_password": _("The old password is incorrect.")})

        # Validate the new password using Django's built-in validators
        password_validation.validate_password(data['new_password'], user)
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        logger.info(f"User {user.email} changed their password.")
        return user