import os
import secrets


os.environ["SECRET_KEY"] = secrets.token_urlsafe(32)