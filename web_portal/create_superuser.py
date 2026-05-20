from django.contrib.auth import get_user_model
User = get_user_model()
email = 'admin@example.com'
password = 'admin_password'
if not User.objects.filter(email=email).exists():
    User.objects.create_superuser(email, password)
    print(f"Superuser {email} created.")
else:
    print(f"Superuser {email} already exists.")
