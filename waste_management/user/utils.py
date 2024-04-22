import random
from django.core.mail import send_mail
from waste_management.settings import EMAIL_HOST_USER
from datetime import datetime
# from django_otp import devices_for_user
# from django_otp.plugins.otp_totp.models import TOTPDevice

def send_and_return_otp(email):
    """Generate and send a One-Time Password (OTP) to the provided email address.

    Parameters:
    - email (str): The email address to which the OTP will be sent.

    Returns:
    - otp (str): The generated OTP."""

    otp = ''.join(random.choices('0123456789', k=6))
    subject = 'Your OTP for verification'
    message = f'Your OTP is: {otp}'
    from_email = EMAIL_HOST_USER  # Use configured email host user
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)
    print("email sent successfully")
    return otp

def generate_otp(user):
    otp = ''.join(random.choices('0123456789', k=6))
    user.otp = otp
    user.otp_timestamp = datetime.now()
    user.save()
    return otp

def verify_otp(user, otp):
    if user.otp and int(user.otp) == int(otp):
        user.otp = None
        user.otp_timestamp = None
        user.save()
        return True
    return False

class MessageError:
    """Class for check error messages"""
    def get_error_messages(self, serializer):
        """Method for return error messages if occure"""
        messages = []
        for msg in tuple(serializer.errors.values()):
            if type(msg) is list:
                messages.append(msg[0])
            else:
                for ele in msg.values():
                    messages.append(ele[0])
        return messages


def get_response_data(user):
    """ method for return user information """

    return {
        'email': user.email,
        'first_name': user.details.first_name,
        'last_name': user.details.last_name,
        # 'phone': '+' + str(user.details.phone.country_code) + ' ' + str(
        #     user.details.phone.national_number),
        'is_phone_verified': user.details.is_phone_verified,
        'is_email_verified': user.is_email_verified,
        'is_active': user.is_active,
        'is_staff': user.is_staff,
        'username': user.username,
        'address': user.details.address,
        'dob': user.details.dob,
        'gender': user.details.gender,
        # 'connected_brokers': user.details.connected_brokers,
        # 'authentication_provider': user.authentication_provider,
        # 'is_two_factor_enabled': user.details.is_two_factor_enabled,
    }