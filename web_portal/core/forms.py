"""
AVAGuard Web Portal - Forms

Hardened forms with NIST-compliant validation.
"""

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .validators import (
    NISTPasswordValidator,
    validate_email_domain,
    validate_email_format,
    sanitize_input,
)

User = get_user_model()


class LoginForm(forms.Form):
    """
    Login form with strict input validation.
    """
    email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'Email address',
            'autocomplete': 'email',
            'required': True,
        })
    )
    password = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Password',
            'autocomplete': 'current-password',
            'required': True,
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower().strip()
        
        # Validate format
        validate_email_format(email)
        
        # Check for disposable domains
        validate_email_domain(email)
        
        # Sanitize
        return sanitize_input(email, max_length=254)
    
    def clean_password(self):
        password = self.cleaned_data.get('password', '')
        
        # Basic sanitization (don't modify password too much)
        if len(password) > 128:
            raise ValidationError("Password too long.")
        
        # Check for null bytes or control characters
        if any(ord(c) < 32 for c in password):
            raise ValidationError("Invalid characters in password.")
        
        return password


class OTPForm(forms.Form):
    """
    OTP verification form with strict validation.
    """
    code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input otp-input',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]{6}',
            'required': True,
            'maxlength': '6',
        })
    )
    session_id = forms.CharField(widget=forms.HiddenInput())
    
    def clean_code(self):
        code = self.cleaned_data.get('code', '')
        
        # Must be exactly 6 digits
        if not code.isdigit() or len(code) != 6:
            raise ValidationError("Code must be exactly 6 digits.")
        
        return code


class RegistrationForm(forms.Form):
    """
    User registration form with NIST password requirements.
    """
    email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'Email address',
        })
    )
    first_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'First name',
        })
    )
    last_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Last name',
        })
    )
    password = forms.CharField(
        min_length=12,
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Password (min 12 chars)',
        })
    )
    confirm_password = forms.CharField(
        min_length=12,
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Confirm password',
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower().strip()
        validate_email_format(email)
        validate_email_domain(email)
        
        if User.objects.filter(email=email).exists():
            raise ValidationError("An account with this email already exists.")
        
        return sanitize_input(email, max_length=254)
    
    def clean_first_name(self):
        name = self.cleaned_data.get('first_name', '').strip()
        return sanitize_input(name, max_length=30)
    
    def clean_last_name(self):
        name = self.cleaned_data.get('last_name', '').strip()
        return sanitize_input(name, max_length=30)
    
    def clean_password(self):
        password = self.cleaned_data.get('password', '')
        
        # NIST validation
        validator = NISTPasswordValidator(min_length=12)
        validator.validate(password)
        
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm = cleaned_data.get('confirm_password')
        
        if password and confirm and password != confirm:
            raise ValidationError("Passwords do not match.")
        
        return cleaned_data


class PasswordChangeForm(forms.Form):
    """
    Password change form with NIST requirements.
    """
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Current password',
        })
    )
    new_password = forms.CharField(
        min_length=12,
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'New password (min 12 chars)',
        })
    )
    confirm_password = forms.CharField(
        min_length=12,
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Confirm new password',
        })
    )
    
    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        current = self.cleaned_data.get('current_password', '')
        
        if self.user and not self.user.check_password(current):
            raise ValidationError("Current password is incorrect.")
        
        return current
    
    def clean_new_password(self):
        password = self.cleaned_data.get('new_password', '')
        
        # NIST validation with user context
        validator = NISTPasswordValidator(min_length=12)
        validator.validate(password, user=self.user)
        
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        new_pass = cleaned_data.get('new_password')
        confirm = cleaned_data.get('confirm_password')
        
        if new_pass and confirm and new_pass != confirm:
            raise ValidationError("New passwords do not match.")
        
        # Cannot reuse current password
        current = cleaned_data.get('current_password')
        if current and new_pass and current == new_pass:
            raise ValidationError("New password cannot be the same as current password.")
        
        return cleaned_data


class UserEditForm(forms.ModelForm):
    """
    Admin form for editing user details.
    """
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'role', 'is_active']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-input'}),
            'first_name': forms.TextInput(attrs={'class': 'form-input'}),
            'last_name': forms.TextInput(attrs={'class': 'form-input'}),
            'role': forms.Select(attrs={'class': 'form-select'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }
