from rest_framework import serializers
from user.models import CustomUser, UserOtherDetails
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils import timezone
from user.utils import *



class UserOtherDetailSerializer(serializers.ModelSerializer):
    address = serializers.CharField(label='Address', required=False)
    first_name = serializers.CharField(label='First Name', required=False)
    last_name = serializers.CharField(label='Last Name', required=False)
    gender = serializers.CharField(label='Gender', required=False)
    dob = serializers.DateField(required=False)

    class Meta:
        model = UserOtherDetails
        fields = ("address", "phone", "first_name", "last_name", "dob", "gender")


class RegisterUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label='Username', required=True)
    email = serializers.EmailField(label='Email', required=True)
    password = serializers.CharField(label='Password', required=True)
    user_other_detail = UserOtherDetailSerializer()
    confirm_password = serializers.CharField(label='Confirm Password', required=True)

    class Meta:
        model = CustomUser
        fields = ('email', 'password', 'confirm_password', 'username', 'user_other_detail')

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use")
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        user_other_detail_data = validated_data.pop('user_other_detail')
        password = validated_data.pop('password')
        confirm_password = validated_data.pop('confirm_password')
        
        user = CustomUser.objects.create(**validated_data)
        user.set_password(password)
        user.is_active = True  # Set user as active
        user.save()

        # Create UserOtherDetails instance
        UserOtherDetails.objects.create(user=user, **user_other_detail_data)
        email = user.email
        print("email-------",email)
        generated_otp = send_and_return_otp(email)
        print("generated_otp",generated_otp)
        user_details = UserOtherDetails.objects.get_or_create(user=user)[0]
        user_details.otp = generated_otp
        user_details.save()
        return user


class LoginSerializer(serializers.ModelSerializer):
    """
    Serializer class for user authentication.

    This serializer is used for authenticating users based on email and password.

    Attributes:
        Meta: Specifies the model and fields to include.
    """

    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        """
        Validate user credentials and generate access and refresh tokens.

        Args:
            attrs (dict): Input attributes containing email and password.

        Returns:
            dict: Validated attributes containing access and refresh tokens.
        """
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = CustomUser.objects.filter(email=email).first()

        if not user:
            raise serializers.ValidationError(
                'No user found with the provided email, try again')

        if not check_password(password, user.password):
            raise serializers.ValidationError('Invalid credentials, try again')

        if not user.is_active:
            raise serializers.ValidationError(
                'Account disabled, contact admin')

        if not user.is_email_verified:
            user.details.generate_otp()
            raise serializers.ValidationError('Please verify your email')

        refresh = RefreshToken.for_user(user)
        attrs['access'] = str(refresh.access_token)
        attrs['refresh'] = str(refresh)
        attrs.pop("email")
        attrs.pop("password")
        return attrs


class VerifyOtpSerializer(serializers.Serializer):
    """
    Serializer for verifying OTP for email verification.

    Attributes:
        email (EmailField): The email of the user.
        otp (IntegerField): The OTP entered by the user.

    Methods:
        validate(attrs): Validates the email and OTP entered by the user.
            Args:
                attrs (dict): The attributes to be validated.
            Returns:
                dict: The validated data.
            Raises:
                ValidationError: If the OTP is incorrect.
    """
    email = serializers.EmailField()
    otp = serializers.IntegerField()

    def validate(self, attrs):

        email = attrs['email']
        otp = attrs['otp']
        user = CustomUser.objects.filter(email=email).first()
        if not user.details.verify_otp(otp):
            raise serializers.ValidationError("Wrong Otp please try again")
        user.is_email_verified = True
        user.save()
        validated_data = super().validate(attrs)
        return validated_data



class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=False)

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        if not attrs.get('refresh'):
            raise serializers.ValidationError(
                detail='Refresh token is required.')
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            raise serializers.ValidationError(
                detail='Token is expired or invalid.')


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('email', 'id')


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.CharField(label='Email', required=True)

    def validate(self, data):
        email = data.get('email', None)

        if email:
            if not CustomUser.objects.filter(email=email):
                raise serializers.ValidationError(
                    """Oops, this email does not exist on our records.
                        Please try again or Sign Up.""")
        return data


class ResetPasswordSerializer(serializers.Serializer):

    email = serializers.EmailField(label='Email', required=True)
    otp = serializers.IntegerField(label='Otp', required=True)
    new_password = serializers.CharField(label='Password', required=True)
    confirm_new_password = serializers.CharField(label='Confirm Password',
                                                 required=True)

    def validate_email(self, email):
        if not CustomUser.objects.filter(email=email):
            raise serializers.ValidationError("Invalid email")
        return email

    def validate(self, data):
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')
        if new_password != confirm_new_password:
            raise serializers.ValidationError("Password and confirm password "
                                              "does not match.")
        return data

class UserOtherDetailsUpdateSerializer(serializers.ModelSerializer):
    address = serializers.CharField(label='Address', required=False)
    first_name = serializers.CharField(label='First Name', required=False)
    last_name = serializers.CharField(label='Last Name', required=False)
    gender = serializers.CharField(label='Gender', required=False)
    dob = serializers.DateField(required=False)
    phone = serializers.CharField(label='Phone', required=False)

    class Meta:
        model = UserOtherDetails
        fields = ('address', 'first_name', 'last_name', 'gender', 'dob', 'phone')

class CustomUserSerializer(serializers.Serializer):
    details = UserOtherDetailsUpdateSerializer(required=False)  

    class Meta:
        model = CustomUser
        fields = ("email", "details")

    def create(self, validated_data):
        details_data = validated_data.pop('details', None)
        user = CustomUser.objects.create(**validated_data)
        if details_data:
            UserOtherDetails.objects.create(user=user, **details_data)
        return user

    def update(self, instance, validated_data):
        details_data = validated_data.pop('details', {})
        details_serializer = self.fields['details']
        for attr, value in details_data.items():
            setattr(instance.details, attr, value)
        instance.details.save()
        return instance