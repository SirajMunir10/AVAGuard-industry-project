import os
import sys

# Get the path of the web_portal directory and root directory
web_portal_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(web_portal_dir)

# Add directories to system path so Django and Core imports work
sys.path.append(web_portal_dir)
sys.path.append(os.path.join(root_dir, 'avaguard-core'))

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Import the WSGI application
from config.wsgi import application

# Vercel requires a variable named 'app'
app = application
