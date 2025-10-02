from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import exceptions

class CookieJWTAuthentication(JWTAuthentication):
    """
    Authenticate using the 'access_token' HttpOnly cookie (browser-friendly).
    - Enforces token_type == 'access'
    - Honors `av` (auth_version) to invalidate stale sessions immediately
    """

    def authenticate(self, request):
        raw_token = request.COOKIES.get('access_token')
        if not raw_token:
            return None  # No cookie, fall back to other auth classes (if any)

        validated_token = self.get_validated_token(raw_token)

        token_type = validated_token.get('token_type', 'access')
        if token_type != 'access':
            raise exceptions.AuthenticationFailed('Invalid token type', code='invalid_token')

        user = self.get_user(validated_token)

        # Optional but recommended: expire access token if auth_version has been bumped
        av_claim = validated_token.get('av', None)
        if av_claim is not None and hasattr(user, 'auth_version') and user.auth_version is not None:
            try:
                if int(av_claim) != int(user.auth_version):
                    raise exceptions.AuthenticationFailed(
                        'Session expired due to account changes', code='stale_token'
                    )
            except (TypeError, ValueError):
                raise exceptions.AuthenticationFailed('Invalid token claim', code='invalid_token')

        return (user, validated_token)
