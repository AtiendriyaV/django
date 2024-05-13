import pyotp
from datetime import datetime, timedelta
import secrets
from accounts.models import UserProfile

def generate_otp_secret():
    # Generate a random base32-encoded secret key
    return pyotp.random_base32()

def send_otp(request, user):
    # Generate an OTP secret key
    secret_key = generate_otp_secret()

    # Create a TOTP instance with the secret key and a time interval of 60 seconds
    totp = pyotp.TOTP(secret_key, interval=60)

    # Generate the OTP
    otp = totp.now()

    # Save OTP secret to user profile (you may need to adjust this based on your model structure)
    user_profile, _ = UserProfile.objects.get_or_create(user=user)
    user_profile.otp_secret = secret_key
    user_profile.save()

    # Store the secret key and the valid until date in the session
    request.session['otp_secret_key'] = secret_key
    valid_until = datetime.now() + timedelta(minutes=1)
    request.session['otp_valid_until'] = str(valid_until)

    # Print or send the OTP (in this example, it's printed to the console)
    print(f"Your OTP is: {otp}")

from accounts.models import UserProfile

def get_user_profile(user):
    try:
        return UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        return None
    