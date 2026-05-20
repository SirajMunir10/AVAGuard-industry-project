"""
AVAGuard Web Portal - Security Validators

NIST-compliant password validation and input sanitization.
"""

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


# Common passwords to reject (top 100 most common)
COMMON_PASSWORDS = {
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    'qwerty', 'qwerty123', 'abc123', 'monkey', 'letmein', 'dragon',
    'sunshine', 'princess', 'welcome', 'shadow', 'superman', 'admin',
    'administrator', 'passw0rd', 'master', 'login', 'hello', 'charlie',
    'donald', 'password1!', 'qwertyuiop', 'whatever', 'trustno1', 'iloveyou',
    'starwars', 'football', 'baseball', 'soccer', 'hockey', 'batman',
    'jordan', 'harley', 'hunter', 'ranger', 'buster', 'thomas',
    'tigger', 'robert', 'soccer1', 'mike', 'jordan23', 'zaq1zaq1',
    'asdfghjkl', '1234567890', 'azerty', 'access', 'mustang', 'michael',
    'pass123', 'summer', 'george', 'bailey', 'password2', 'killer',
}

# Disposable email domains to reject
DISPOSABLE_DOMAINS = {
    'tempmail.com', 'throwaway.email', 'guerrillamail.com', 'mailinator.com',
    'temp-mail.org', '10minutemail.com', 'fakemailgenerator.com', 'yopmail.com',
    'maildrop.cc', 'dispostable.com', 'trashmail.com', 'getairmail.com',
}


class NISTPasswordValidator:
    """
    Validate passwords according to NIST SP 800-63B guidelines.
    
    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Not in common password list
    """
    
    def __init__(self, min_length=12):
        self.min_length = min_length
    
    def validate(self, password, user=None):
        errors = []
        
        # Minimum length
        if len(password) < self.min_length:
            errors.append(
                ValidationError(
                    _(f"Password must be at least {self.min_length} characters long."),
                    code='password_too_short',
                )
            )
        
        # Uppercase requirement
        if not re.search(r'[A-Z]', password):
            errors.append(
                ValidationError(
                    _("Password must contain at least one uppercase letter (A-Z)."),
                    code='password_no_upper',
                )
            )
        
        # Lowercase requirement
        if not re.search(r'[a-z]', password):
            errors.append(
                ValidationError(
                    _("Password must contain at least one lowercase letter (a-z)."),
                    code='password_no_lower',
                )
            )
        
        # Digit requirement
        if not re.search(r'\d', password):
            errors.append(
                ValidationError(
                    _("Password must contain at least one number (0-9)."),
                    code='password_no_digit',
                )
            )
        
        # Special character requirement
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
            errors.append(
                ValidationError(
                    _("Password must contain at least one special character (!@#$%^&* etc)."),
                    code='password_no_special',
                )
            )
        
        # Common password check
        if password.lower() in COMMON_PASSWORDS:
            errors.append(
                ValidationError(
                    _("This password is too common. Please choose a more secure password."),
                    code='password_too_common',
                )
            )
        
        # Check for user-related info in password
        if user is not None:
            user_attrs = ['email', 'first_name', 'last_name', 'username']
            for attr in user_attrs:
                value = getattr(user, attr, None)
                if value and len(value) > 3 and value.lower() in password.lower():
                    errors.append(
                        ValidationError(
                            _("Password cannot contain your personal information."),
                            code='password_contains_user_info',
                        )
                    )
                    break
        
        if errors:
            raise ValidationError(errors)
    
    def get_help_text(self):
        return _(
            f"Your password must be at least {self.min_length} characters and include: "
            "uppercase letters, lowercase letters, numbers, and special characters."
        )


def validate_email_domain(email):
    """
    Validate that email is not from a disposable/temporary email service.
    """
    if not email:
        return
    
    try:
        domain = email.lower().split('@')[1]
    except IndexError:
        raise ValidationError(_("Invalid email format."))
    
    if domain in DISPOSABLE_DOMAINS:
        raise ValidationError(
            _("Temporary or disposable email addresses are not allowed."),
            code='disposable_email',
        )


def validate_email_format(email):
    """
    Strict RFC 5322 email format validation.
    """
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        raise ValidationError(
            _("Please enter a valid email address."),
            code='invalid_email_format',
        )


def sanitize_input(value, max_length=255, allow_html=False):
    """
    Sanitize user input to prevent XSS and injection attacks.
    """
    if not value:
        return value
    
    # Truncate to max length
    value = str(value)[:max_length]
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    if not allow_html:
        # Escape HTML entities
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&#x27;')
    
    return value.strip()
