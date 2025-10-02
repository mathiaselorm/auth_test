from datetime import datetime, timedelta, timezone
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.middleware.csrf import get_token
from django.utils.translation import gettext_lazy as _

from rest_framework import generics, status, serializers
from rest_framework.decorators import api_view
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle

from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    inline_serializer,
)

from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from django_rest_passwordreset.views import (
    ResetPasswordRequestToken,
    ResetPasswordConfirm,
    ResetPasswordValidateToken,
)

from .permissions import IsAdmin
from .email_utils import send_password_change_email
from .serializers import (
    UserRegistrationSerializer,
    PublicUserRegistrationSerializer,
    CustomTokenObtainPairSerializer,
    PasswordChangeSerializer,
    UserSerializer,
)

logger = logging.getLogger(__name__)
User = get_user_model()


# ----------------------------
# Helpers
# ----------------------------

def _seconds_until_exp(jwt_token_obj):
    """
    Compute seconds until token expiration from its 'exp' claim.
    Returns None if the claim cannot be read (caller will fall back).
    """
    try:
        exp = int(jwt_token_obj.get('exp'))
        now = datetime.now(timezone.utc).timestamp()
        secs = int(exp - now)
        return max(secs, 0)
    except Exception:
        return None


def set_auth_cookies(response, access_token_obj, refresh_token_obj, remember_me=False, request=None):
    """
    Set access_token and refresh_token as HttpOnly cookies.
    Also sets a CSRF cookie explicitly.

    - Cookie lifetimes are aligned exactly with token 'exp' when available.
    - Falls back to SIMPLE_JWT lifetimes if 'exp' can't be read.
    """
    access_max = _seconds_until_exp(access_token_obj)
    refresh_max = _seconds_until_exp(refresh_token_obj)

    if access_max is None:
        access_max = int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds())
    if refresh_max is None:
        fallback = timedelta(days=5) if remember_me else api_settings.REFRESH_TOKEN_LIFETIME
        refresh_max = int(fallback.total_seconds())

    cookie_domain = getattr(settings, 'SESSION_COOKIE_DOMAIN', None)

    response.set_cookie(
        key="access_token",
        value=str(access_token_obj),
        httponly=True,
        secure=True,
        samesite="None",
        max_age=access_max,
        domain=cookie_domain,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=str(refresh_token_obj),
        httponly=True,
        secure=True,
        samesite="None",
        max_age=refresh_max,
        domain=cookie_domain,
        path="/",
    )

    # Ensure CSRF cookie is present and readable by frontend (NOT HttpOnly)
    if request is not None:
        csrf = get_token(request)
        response.set_cookie(
            key="csrftoken",
            value=csrf,
            httponly=False,
            secure=True,
            samesite="None",
            max_age=None,  # session cookie is fine for CSRF
            domain=cookie_domain,
            path="/",
        )


def delete_auth_cookies(response):
    """Delete access_token, refresh_token, and csrftoken cookies on the given response."""
    cookie_domain = getattr(settings, 'SESSION_COOKIE_DOMAIN', None)
    for name in ('refresh_token', 'access_token', 'csrftoken'):
        response.delete_cookie(name, domain=cookie_domain, path='/')


# ----------------------------
# Throttles (optional but recommended)
# ----------------------------

# class LoginAnonThrottle(AnonRateThrottle):
#     # Adjust to taste or move to settings if you prefer
#     rate = '10/min'


# class PasswordResetAnonThrottle(AnonRateThrottle):
#     rate = '5/min'


# ----------------------------
# Views
# ----------------------------

@extend_schema(
    summary="Register a new user",
    description="Registers a new user account. Only authenticated users with Admin privileges can register new users.",
    request=UserRegistrationSerializer,
    responses={
        201: OpenApiResponse(description="User registered successfully. An email has been sent to set their password."),
        400: OpenApiResponse(description="Bad Request. Validation errors occurred."),
        500: OpenApiResponse(description="Internal Server Error. An unexpected error occurred."),
    },
    tags=["Authentication"],
)
class UserRegistrationView(generics.CreateAPIView):
    """
    API endpoint for registering a new user.
    Permissions: Only authenticated users with Admin privileges can register new users.
    """
    serializer_class = UserRegistrationSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        logger.info(f"User created: {user.get_full_name()} (ID: {user.id}) by admin {request.user.email}")
        return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)


@extend_schema(
    summary="Public User Registration",
    description=(
        "Allows anyone to register a new user account. "
        "Users can select their role (Manager or Supervisor) or default to Supervisor if not specified. "
        "Admin role cannot be selected during public registration. "
        "No admin permissions required. Users can immediately log in after registration."
    ),
    request=PublicUserRegistrationSerializer,
    responses={
        201: OpenApiResponse(
            description="User registered successfully.",
            response=inline_serializer(
                name="PublicRegistrationResponse",
                fields={
                    "message": serializers.CharField(),
                    "user": UserSerializer(),
                }
            )
        ),
        400: OpenApiResponse(description="Validation error."),
        500: OpenApiResponse(description="Internal Server Error."),
    },
    tags=["Public Registration"],
)
class PublicUserRegistrationView(generics.CreateAPIView):
    """
    API endpoint for public user registration.
    Permissions: Anyone can register (AllowAny).
    Users can select their role (Manager or Supervisor) or default to Supervisor.
    Admin role is restricted and cannot be selected during public registration.
    """
    serializer_class = PublicUserRegistrationSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Return user data (excluding sensitive information)
        user_data = UserSerializer(user).data
        
        logger.info(f"Public user registered: {user.get_full_name()} ({user.email})")
        return Response({
            "message": "Registration successful! You can now log in with your credentials.",
            "user": user_data
        }, status=status.HTTP_201_CREATED)


@extend_schema(
    summary="Obtain JWT tokens via cookies",
    description=(
        "Authenticates the user and sets JWT access and refresh tokens as HttpOnly cookies. "
        "A CSRF token is also set. Tokens are NOT returned in the response body. "
        "If `remember_me` is true, the refresh token's lifetime is extended."
    ),
    request=inline_serializer(
        name="TokenObtainPairRequest",
        fields={
            "email": serializers.CharField(help_text="The email of the user"),
            "password": serializers.CharField(help_text="The password of the user", style={"input_type": "password"}),
            "remember_me": serializers.BooleanField(required=False, default=False, help_text="If true, tokens are given extended lifetimes."),
        },
    ),
    responses={
        200: OpenApiResponse(description="Authentication successful. Tokens set in HttpOnly cookies."),
        400: OpenApiResponse(description="Invalid credentials or bad request."),
    },
    tags=["Authentication"],
)
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    API endpoint for obtaining JWT tokens.
    Tokens are set as secure, HttpOnly cookies for enhanced security.
    """
    serializer_class = CustomTokenObtainPairSerializer
    # throttle_classes = [LoginAnonThrottle]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed:
            raise DRFValidationError({"detail": "Invalid credentials."})

        refresh = serializer.refresh_token_obj
        access = serializer.access_token_obj
        remember_me = bool(getattr(serializer, 'remember_me_bool', False))

        response = Response({"message": "Authentication successful. Tokens set in cookies."},
                            status=status.HTTP_200_OK)
        set_auth_cookies(response, access, refresh, remember_me, request)
        logger.info(f"User {serializer.user.email} logged in. Tokens set in cookies.")
        return response


@extend_schema(
    summary="Refresh JWT access token",
    description=(
        "Refreshes the JWT access token using the refresh token stored in HttpOnly cookies. "
        "Sets a new access token and, if rotation is enabled, a new refresh token as HttpOnly cookies. "
        "No request body is required."
    ),
    responses={
        200: OpenApiResponse(description="Access token refreshed successfully. Tokens set in HttpOnly cookies."),
        400: OpenApiResponse(description="Refresh token not found or invalid."),
        401: OpenApiResponse(description="Unauthorized. Refresh token expired, blacklisted, or invalid."),
    },
    tags=["Authentication"],
)
class CustomTokenRefreshView(generics.GenericAPIView):
    """
    API endpoint for refreshing JWT access tokens from cookies.
    """
    permission_classes = []  # refresh based on cookie only

    def post(self, request, *args, **kwargs):
        refresh_token_str = request.COOKIES.get("refresh_token")
        if not refresh_token_str:
            return Response({"error": "Refresh token not found"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            old_refresh_token = RefreshToken(refresh_token_str)
            user_id = old_refresh_token.get('user_id')

            # Load the user FIRST
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                logger.warning(f"Refresh attempt with token for non-existent user ID: {user_id}")
                resp = Response({"error": "Associated user not found."}, status=status.HTTP_401_UNAUTHORIZED)
                delete_auth_cookies(resp)
                return resp

            # Enforce auth_version invalidation
            av_claim = int(old_refresh_token.get('av', 1))
            if av_claim != user.auth_version:
                resp = Response({"error": "Session expired due to account changes. Please log in again."},
                                status=status.HTTP_401_UNAUTHORIZED)
                delete_auth_cookies(resp)
                return resp

            # Infer remember_me gracefully (supports legacy tokens without the claim)
            def _infer_remember_me(tok):
                claim = tok.get('remember_me', None)
                if claim is not None:
                    return bool(claim)
                try:
                    exp = int(tok.get('exp')); iat = int(tok.get('iat'))
                    default_secs = int(api_settings.REFRESH_TOKEN_LIFETIME.total_seconds())
                    return (exp - iat) > default_secs
                except Exception:
                    return False

            remember_me = _infer_remember_me(old_refresh_token)

            # Prepare new tokens
            new_access_token = old_refresh_token.access_token
            new_access_token['av'] = user.auth_version  # ensure access token carries latest av
            new_refresh_token_obj = old_refresh_token

            if api_settings.ROTATE_REFRESH_TOKENS:
                # Try to blacklist the old refresh token
                try:
                    old_refresh_token.blacklist()
                    logger.info(f"Old refresh token for user {user.email} blacklisted during refresh.")
                except Exception as e:
                    logger.warning(f"Failed to blacklist old refresh token for user {user.email}: {e}")

                # Mint a new refresh token
                new_refresh = RefreshToken.for_user(user)
                if remember_me:
                    new_refresh.set_exp(lifetime=timedelta(days=5))
                new_refresh['remember_me'] = remember_me
                new_refresh['av'] = user.auth_version

                new_access_token = new_refresh.access_token
                new_access_token['av'] = user.auth_version
                new_refresh_token_obj = new_refresh

            response = Response({"message": "Access token refreshed successfully."},
                                status=status.HTTP_200_OK)
            set_auth_cookies(response, new_access_token, new_refresh_token_obj, remember_me, request)
            logger.info(f"Access token refreshed for user {user.email}.")
            return response

        except TokenError as e:
            logger.error(f"JWT Token refresh error for {request.COOKIES.get('refresh_token', 'N/A')}: {e}")
            resp = Response({"error": "Token is invalid or expired. Please log in again."},
                            status=status.HTTP_401_UNAUTHORIZED)
            delete_auth_cookies(resp)
            return resp
        except Exception as e:
            logger.exception(f"An unexpected error occurred during token refresh: {e}")
            return Response({"error": "An internal server error occurred during token refresh."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@extend_schema(
    summary="Request Password Reset",
    description="Initiates the password reset process. Provide your email address, and if an account with that email exists, a password reset token is generated and sent via email.",
    request=inline_serializer(
            name="PasswordResetRequest",
            fields={
                "email": serializers.EmailField(
                    help_text="The email address of the user who forgot their password."
                )
            }
        ),
    responses={
        200: OpenApiResponse(description="Password reset e-mail has been sent."),
    },
    tags=["Password Reset"],
)
class CustomPasswordResetRequestView(ResetPasswordRequestToken):
    """
    API endpoint to initiate a password reset.
    """
    # throttle_classes = [PasswordResetThrottle]

    def get_user_by_email(self, email):
        email = email.strip()
        try:
            return User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise None


@extend_schema(
    operation_id="password_reset_confirm",
    tags=["Password Reset"],
    summary="Confirm Password Reset",
    description="Confirms password reset with a valid token."
)
class CustomPasswordResetConfirmView(ResetPasswordConfirm):
    pass


@extend_schema(
    operation_id="password_reset_validate_token",
    tags=["Password Reset"],
    summary="Validate Password Reset Token",
    description="Validates a password reset token."
)
class CustomPasswordResetValidateView(ResetPasswordValidateToken):
    pass


@extend_schema(
    summary="Change password for authenticated user",
    description="Change password for the authenticated user.",
    request=PasswordChangeSerializer,
    responses={
        200: OpenApiResponse(description="Password changed successfully."),
        400: OpenApiResponse(description="Bad Request due to invalid input."),
    },
    tags=["Password Management"],
)
class PasswordChangeView(generics.UpdateAPIView):
    """
    An endpoint for changing the password of the authenticated user.
    """
    http_method_names = ['patch']
    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = self.get_object()
        serializer.save()
        # Send synchronous notification
        email_sent = send_password_change_email(user.id)
        if not email_sent:
            logger.warning(f"Password change email failed to send for user {user.id}")
        return Response({"detail": _("Your password has been changed successfully.")}, status=status.HTTP_200_OK)


@extend_schema(
    summary="Logout",
    description="Logs out the user by blacklisting the refresh token if present, then deletes all authentication-related cookies.",
    responses={
        200: OpenApiResponse(description="Logged out successfully."),
        400: OpenApiResponse(description="Bad Request due to missing refresh token or token error."),
    },
    tags=["Authentication"],
)
@api_view(['POST'])
def logout_view(request):
    """
    Logs out the user by blacklisting the refresh token (if present) and
    deleting all authentication-related cookies (access_token, refresh_token, csrftoken).
    """
    refresh_token = request.COOKIES.get('refresh_token')
    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"Refresh token blacklisted for user: {getattr(request.user, 'email', 'anonymous')}")
        except TokenError as e:
            logger.warning(f"Error blacklisting refresh token (it might be invalid or expired): {e}")
        except Exception as e:
            logger.error(f"Unexpected error during refresh token blacklisting: {e}")
    else:
        logger.info("Logout attempt without refresh token in cookies.")

    response = Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
    delete_auth_cookies(response)
    return response


@extend_schema(
    summary="List Users (Admin Only)",
    description="Lists all user accounts. Requires Admin privileges.",
    responses={
        200: OpenApiResponse(description="List of users retrieved successfully.", response=UserSerializer(many=True)),
        403: OpenApiResponse(description="Permission Denied."),
    },
    tags=["User Management"],
)
class UserListView(generics.ListAPIView):
    """
    List all user accounts. Only accessible by Admin users.
    """
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    queryset = User.objects.all().order_by('id')

    def get(self, request, *args, **kwargs):
        logger.info(f"Admin user {request.user.get_full_name()} accessed the user list.")
        return super().get(request, *args, **kwargs)



@extend_schema(
    summary="User Details by ID (Admin Only)",
    description=(
        "Retrieve, update, or delete any user's account by their ID.\n"
        "- GET: Retrieves user's details by ID.\n"
        "- PATCH: Updates user's details by ID.\n"
        "- DELETE: Deletes user's account by ID.\n"
        "- Permissions: Only authenticated users with Admin privileges can perform these actions."
    ),
    responses={
        200: OpenApiResponse(description="User data retrieved or updated successfully", response=UserSerializer),
        204: OpenApiResponse(description="User account deleted successfully"),
        400: OpenApiResponse(description="Validation error"),
        401: OpenApiResponse(description="Authentication credentials were not provided."),
        403: OpenApiResponse(description="Permission denied."),
        404: OpenApiResponse(description="User not found."),
    },
    tags=["User Management"],
)
class UserDetailRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint for retrieving, updating, and deleting user accounts by ID.
    Only accessible by Admin users.
    """
    http_method_names = ['get', 'patch', 'delete']
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        logger.info(f"Admin user {request.user.email} retrieved profile for user ID: {instance.id}.")
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        logger.info(f"Admin user {request.user.email} updated profile for user ID: {instance.id}.")
        return Response(serializer.data)

    @extend_schema(
        operation_id="delete_user_by_id",
        summary="Delete User by ID (Admin Only)",
        description=(
            "Deletes a specific user account by their ID. Requires Admin privileges. "
            "Administrators cannot delete their own account using this endpoint."
        ),
        request=None,
        responses={
            204: OpenApiResponse(description="User account deleted successfully. No content returned.", response=None),
            403: OpenApiResponse(
                description="Permission denied. This can happen if a non-admin attempts to delete, "
                            "or if an admin attempts to self-delete.",
                response=inline_serializer(
                    name="ForbiddenDeleteResponse",
                    fields={"detail": serializers.CharField(default="Permission denied.")},
                ),
            ),
        },
        tags=["User Management"],
    )
    def delete(self, request, *args, **kwargs):
        user_to_delete = self.get_object()
        requester_email = getattr(request.user, 'email', 'N/A')
        logger.info(f"Admin user {requester_email} attempting to delete user {user_to_delete.email} (ID: {user_to_delete.id}).")

        # Prevent self-delete via this endpoint
        if request.user.id == user_to_delete.id:
            logger.warning(f"Admin {requester_email} attempted to self-delete via UserDetailRetrieveUpdateDestroyView.")
            return Response(
                {"detail": "Administrators cannot delete their own account using this endpoint. Please use Django admin if necessary."},
                status=status.HTTP_403_FORBIDDEN,
            )

        self.perform_destroy(user_to_delete)
        logger.info(f"Admin user {requester_email} successfully deleted user {user_to_delete.email} (ID: {user_to_delete.id}).")
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    summary="Get current user details",
    description="Retrieve the details of the currently authenticated user.",
    responses={
        200: OpenApiResponse(description="Current user details retrieved successfully.", response=UserSerializer),
        401: OpenApiResponse(description="Authentication credentials were not provided."),
    },
    tags=["User Management"],
)
class CurrentUserView(generics.RetrieveAPIView):
    """
    API endpoint for retrieving current user details.
    """
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)