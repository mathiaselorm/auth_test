# Django Authentication API

A robust Django REST API backend with comprehensive user authentication features including JWT token management, email verification, password reset functionality, and custom user management.

## Features

- **Custom User Authentication** - Extended Django user model with custom authentication
- **JWT Token Management** - Access and refresh tokens with automatic rotation and blacklisting
- **Cookie-based JWT Authentication** - Secure HTTP-only cookie implementation
- **Email Verification** - Account activation via email
- **Password Reset** - Secure password reset via email using django-rest-passwordreset
- **CORS Support** - Cross-origin resource sharing for frontend integration
- **API Documentation** - Swagger/OpenAPI documentation with drf-spectacular
- **Email Integration** - Brevo API backend for email services

## Tech Stack

- **Backend Framework**: Django 5.2.6
- **API Framework**: Django REST Framework 3.16.1
- **Authentication**: JWT (djangorestframework-simplejwt 5.5.1)
- **Database**: SQLite (default, configurable)
- **Email Backend**: Brevo API
- **Documentation**: drf-spectacular
- **Environment Management**: django-environ

## Quick Start

### Prerequisites

- Python 3.8+
- pip
- Virtual environment (recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd "Frontend Test"
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   Create a `.env` file in the root directory:
   ```env
   SECRET_KEY=your-secret-key-here
   DEBUG=True
   DEFAULT_FROM_EMAIL=your-email@example.com
   BREVO_API_KEY=your-brevo-api-key
   BREVO_DOMAIN=your-brevo-domain
   ```

5. **Database Setup**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create Superuser (Optional)**
   ```bash
   python manage.py createsuperuser
   ```

7. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

The API will be available at `http://127.0.0.1:8000/`


### API Documentation
- `/api/schema/` - OpenAPI schema
- `/api/docs/` - Swagger UI documentation
- `/api/redoc/` - ReDoc documentation


## Configuration

### JWT Settings
- **Access Token Lifetime**: 15 minutes
- **Refresh Token Lifetime**: 60 minutes
- **Token Rotation**: Enabled
- **Blacklist After Rotation**: Enabled

### CORS Configuration
- All origins allowed (development)
- Credentials supported
- Custom headers for CSRF tokens

### Email Configuration
The project uses Brevo API for email services. Configure the following in your `.env`:
- `BREVO_API_KEY`: Your Brevo API key
- `BREVO_DOMAIN`: Your Brevo domain
- `DEFAULT_FROM_EMAIL`: Default sender email

## Security Features

- **CSRF Protection**: Custom CSRF cookie configuration
- **Secure Cookies**: HTTP-only cookies for JWT tokens
- **Token Blacklisting**: Automatic token invalidation
- **Password Validation**: Django's built-in password validators
- **Information Leakage Prevention**: Configurable for production

## Development

### Running Tests
```bash
python manage.py test
```

### Creating Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Collecting Static Files
```bash
python manage.py collectstatic
```

## Deployment

### Production Settings
1. Set `DEBUG=False` in your environment
2. Configure `ALLOWED_HOSTS` appropriately
3. Set up a production database (PostgreSQL recommended)
4. Configure static file serving
5. Set secure cookie settings

### Environment Variables for Production
```env
SECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DATABASE_URL=your-database-url
BREVO_API_KEY=your-production-brevo-key
```