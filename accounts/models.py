from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
import uuid

class CustomUserManager(BaseUserManager):
    """
    Custom user manager where email is the unique identifier for authentication.
    """
    def create_user(self, email, password=None, user_role=None, first_name=None, last_name=None, phone_number=None, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        
        # Only enforce user_role for non-superusers
        if not extra_fields.get('is_superuser', False) and not user_role:
            raise ValueError(_('The User role must be set'))
        
        email = self.normalize_email(email).lower()
        user = self.model(
            email=email,
            user_role=user_role,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            **extra_fields
        )
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_public_user(self, email, password, first_name=None, last_name=None, phone_number=None, **extra_fields):
        """
        Create a public user with default Supervisor role.
        Designed for public registration without admin intervention.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        if not password:
            raise ValueError(_('Password must be provided for public registration'))
        
        # Set defaults for public users
        extra_fields.setdefault('user_role', UserRole.SUPERVISOR)
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_active', True)
        
        email = self.normalize_email(email).lower()
        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


    def create_superuser(self, email, password, first_name=None, last_name=None, phone_number=None, **extra_fields):
        """
        Create and save a Superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        return self.create_user(email, password, first_name=first_name, last_name=last_name, phone_number=phone_number, **extra_fields)  


class UserRole(models.TextChoices):
    """
    Enumeration for user roles.
    """
    ADMIN = 'admin', _('Admin')
    MANAGER = 'manager', _('Manager')
    SUPERVISOR = 'supervisor', _('Supervisor')


class CustomUser(AbstractUser):
    """
    Custom user model that supports using email as the username.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None  # Disable the username field
    email = models.EmailField(_('email address'), unique=True)
    user_role = models.CharField(
        _('User Role'),
        max_length=25, 
        choices=UserRole.choices,
        default=UserRole.SUPERVISOR, 
        null=True,
        blank=True
    )
    phone_number = models.CharField(_('Phone Number'),max_length=15, blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    auth_version = models.PositiveIntegerField(default=1)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    class Meta:
        app_label = 'accounts'
        db_table = 'custom_user'
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ['-date_joined']
    
        indexes = [
            models.Index(fields=['email'], name='email_idx')
        ]
        

        
    def get_full_name(self):
        return super().get_full_name()

    def __str__(self):
        return f"{self.get_full_name()} ({self.email})"
