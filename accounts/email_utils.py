import logging
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model
from django.utils.html import strip_tags
from django.utils.encoding import force_str

# Initialize logging
logger = logging.getLogger(__name__)

# Get the user model
User = get_user_model()

def mask_email(email):
    """Mask email for logging privacy"""
    name, _, domain = email.partition("@")
    return (name[:2] + "***@" + domain) if domain else "***"

def send_email_safely(email_function, *args, **kwargs):
    """
    Wrapper to handle email sending errors gracefully.
    Returns True if successful, False if failed.
    """
    try:
        return email_function(*args, **kwargs)
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False

def send_welcome_email(user_pk, reset_url):
    """
    Sends a welcome email with a link to set the user's password.
    Returns True if successful, False if failed.
    """
    try:
        user = User.objects.get(pk=user_pk)
        if not user.email:
            logger.error(f"User with pk {user_pk} does not have an email address.")
            return False

        subject = 'Set Your Password'
        context = {
            'user': user,
            'reset_url': reset_url,
        }

        html_content = render_to_string('accounts/account_creation_email.html', context)
        text_content = strip_tags(html_content)

        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        email.attach_alternative(html_content, "text/html")
        sent = email.send()

        if sent:
            logger.info("Welcome email sent to %s", mask_email(user.email))
            return True
        else:
            logger.error("Welcome email send() returned 0 for %s", mask_email(user.email))
            return False

    except User.DoesNotExist:
        logger.error("User %s not found; welcome email not sent.", user_pk)
        return False
    except Exception as e:
        logger.exception("Error sending welcome email to user %s: %s", user_pk, e)
        return False

def send_password_reset_email(user_id, subject, email_template, context):
    """
    Sends a password reset email to the user.
    Returns True if successful, False if failed.
    """
    try:
        user = User.objects.get(pk=user_id)
        if not user.email:
            logger.error(f"User with id {user_id} does not have an email address.")
            return False

        html_content = render_to_string(email_template, context)
        text_content = strip_tags(html_content)

        email = EmailMultiAlternatives(
            subject=force_str(subject),
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        email.attach_alternative(html_content, "text/html")
        sent = email.send()

        if sent:
            logger.info("Password reset email sent to %s", mask_email(user.email))
            return True
        else:
            logger.error("Password reset email send() returned 0 for %s", mask_email(user.email))
            return False

    except User.DoesNotExist:
        logger.error("User %s not found; reset email not sent.", user_id)
        return False
    except Exception as e:
        logger.exception("Error sending password reset email to user %s: %s", user_id, e)
        return False

def send_password_change_email(user_id):
    """
    Sends a password change notification email to the user.
    Returns True if successful, False if failed.
    """
    try:
        user = User.objects.get(pk=user_id)
        if not user.email:
            logger.error(f"User with id {user_id} does not have an email address.")
            return False

        subject = 'Password Changed Successfully'
        context = {
            'user_name': user.get_full_name()
        }
        
        html_content = render_to_string('accounts/password_change.html', context)
        text_content = strip_tags(html_content)

        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        email.attach_alternative(html_content, "text/html")
        sent = email.send()

        if sent:
            logger.info("Password change email sent to %s", mask_email(user.email))
            return True
        else:
            logger.error("Password change email send() returned 0 for %s", mask_email(user.email))
            return False

    except User.DoesNotExist:
        logger.error("User %s not found; change email not sent.", user_id)
        return False
    except Exception as e:
        logger.exception("Error sending password change email to user %s: %s", user_id, e)
        return False