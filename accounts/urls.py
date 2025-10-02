from django.urls import path
from . import views



urlpatterns = [
    # Public Registration endpoint
    path('signup/', views.PublicUserRegistrationView.as_view(), name='public-user-registration'),
    
    # Authentication endpoints
    path('login/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', views.CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', views.logout_view, name='logout'),
    path('me/', views.CurrentUserView.as_view(), name='current-user'),


    # Password Management endpoints
    path('password-reset/request/', views.CustomPasswordResetRequestView.as_view(), name='password_reset'),
    path('password-reset/confirm/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset/validate-token/', views.CustomPasswordResetValidateView.as_view(), name='password_reset_validate_token'),
    path('password/change/', views.PasswordChangeView.as_view(), name='password-change'),
    
    # User management endpoints
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('users/register/', views.UserRegistrationView.as_view(), name='user-registration'),
    path('users/<uuid:pk>/', views.UserDetailRetrieveUpdateDestroyView.as_view(), name='user-details'),
]









