from rest_framework.views import APIView
from rest_framework import generics
from user.serializers import (RegisterUserSerializer,LoginSerializer,LogoutSerializer,VerifyOtpSerializer,
ForgotPasswordSerializer,ResetPasswordSerializer,UserSerializer,CustomUserSerializer, UserOtherDetailsUpdateSerializer)
from rest_framework.response import Response
from user.models import CustomUser, UserOtherDetails
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import permissions, status
from user.permissions import RefreshTokenPermission
from user.utils import MessageError, get_response_data, send_and_return_otp
import logging


logger = logging.getLogger(__name__)


class SignUp(APIView, MessageError):
    """
    API endpoint for user registration.
    This endpoint allows users to register by providing their details.
    Upon successful registration, it returns a JWT access and refresh token.
    Request data should include:
    - email
    - password
    - first_name
    - last_name
    - phone
    - and optionally other user details like address, dob, gender, etc.
    Returns:
    - HTTP 200 OK: User successfully registered with token details.
    - HTTP 400 BAD REQUEST: If request data is invalid.
    - HTTP 500 INTERNAL SERVER ERROR: If an unexpected error occurs during registration.

    """
    def post(self, request):
        """Method fo create user and validate user information"""
        try:
            serializer = RegisterUserSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                response_data = get_response_data(user)
                return Response({"message": "User Created Successfully, Please verify your email first",
                                "data": response_data},
                                status=status.HTTP_200_OK)
            messages = self.get_error_messages(serializer)
            return Response({"message": "Field error: "+", ".join(messages),
                            "data": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.error("Error during user registration: %s", error)
            return Response({"message": "Internal Server Error"},
                            status=status.HTTP_400_BAD_REQUEST)


class LogInView(TokenObtainPairView):
    """
    API endpoint for user login.

    This endpoint allows users to authenticate by providing their email and password.
    Upon successful authentication, it returns a JWT access and refresh token.

    Request data should include:
    - email
    - password

    Returns:
    - HTTP 200 OK: User successfully authenticated with token details.
    - HTTP 400 BAD REQUEST: If request data is invalid or authentication fails.
    - HTTP 500 INTERNAL SERVER ERROR: If an unexpected error occurs during authentication.

    """

    permission_class = (AllowAny,)
    serializer_class = LoginSerializer

    def get_serializer_context(self, *args, **kwargs):
        """
        Override method to pass request context to serializer.

        Returns:
        - context: Dictionary containing request object.

        """
        context = super(LogInView, self).get_serializer_context()
        context.update({'request': self.request})
        return context


class LogoutView(generics.GenericAPIView, MessageError):
    """
    API endpoint for user logout.

    This endpoint allows authenticated users to invalidate their refresh token,
    effectively logging them out.

    Request data should include:
    - refresh

    Returns:
    - HTTP 204 NO CONTENT: If logout is successful.
    - HTTP 400 BAD REQUEST: If request data is invalid.
    - HTTP 500 INTERNAL SERVER ERROR: If an unexpected error occurs during logout.

    """
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        """Method for logout user"""
        try:
            serializer = self.serializer_class(data=request.data)
            print("LogoutSerializer=====",request.data)
            if serializer.is_valid():
                serializer.save()
                # users_logger.info("user logged out successfully")
                return Response({"message": "Logged out successfully"},
                                status=status.HTTP_200_OK)
                # return Response(status=status.HTTP_204_NO_CONTENT)
            messages = self.get_error_messages(serializer)
            return Response({"message": "Field error: "+", ".join(messages),
                            "data": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.error(f"Error during user logout: {error}")
            return Response({"message": "Internal Server Error"},
                            status=status.HTTP_400_BAD_REQUEST)


class VerifyOtpView(generics.GenericAPIView, MessageError):
    """
    API endpoint for verifying OTP.

    This endpoint allows users to verify an OTP (One-Time Password) for authentication.

    Request data should include:
    - otp

    Returns:
    - HTTP 200 OK: If OTP is verified successfully.
    - HTTP 400 BAD REQUEST: If request data is invalid.
    - HTTP 500 INTERNAL SERVER ERROR: If an unexpected error occurs during OTP verification.

    """
    serializer_class = VerifyOtpSerializer
    queryset = CustomUser.objects.none()
    permission_classes = (AllowAny,)

    def post(self, request):
        """Method for verify OTP"""
        try:
            serializer = self.serializer_class(data=request.data)

            if serializer.is_valid():
                return Response({'detail': 'OTP verified successfully'},
                                status=status.HTTP_200_OK)
            messages = self.get_error_messages(serializer)
            return Response({"message": "Field error: "+", ".join(messages),
                             "data": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.error(f"Error during OTP verification: {error}")
            return Response({"message": "Internal Server Error"},
                            status=status.HTTP_400_BAD_REQUEST)


class FetchUsersView(APIView):
    """
    API endpoint for fetching all users.

    This endpoint allows authenticated users to retrieve a list of all registered users.

    Returns:
    - HTTP 200 OK: If users are fetched successfully.
    - HTTP 401 UNAUTHORIZED: If the request is made by an unauthenticated user.

    """
    # permission_classes = [permissions.IsAuthenticated,]

    def get(self, request, format=None):
        """
        Method to handle GET request for fetching all users.

        Returns:
        - HTTP 200 OK: If users are fetched successfully.
        - HTTP 401 UNAUTHORIZED: If the request is made by an unauthenticated user.

        """
        users = CustomUser.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response({"message": "User Fetches Successfully",
                         "data": serializer.data},
                        status=status.HTTP_200_OK)


class ForgotPasswordApiView(APIView, MessageError):
    """
    API endpoint for forgot password.

    This endpoint allows users to request a password reset by providing their email.
    Upon successful request, an OTP will be sent to the user's registered email.

    Request data should include:
    - email

    Returns:
    - HTTP 200 OK: If OTP is sent successfully.
    - HTTP 400 BAD REQUEST: If request data is invalid or user does not exist.
    - HTTP 500 INTERNAL SERVER ERROR: If an unexpected error occurs during the process.

    """
    def post(self, request):
        """
        Method to handle forgot password request.

        Returns:
        - HTTP 200 OK: If OTP is sent successfully.
        - HTTP 400 BAD REQUEST: If request data is invalid or user does not exist.
        - HTTP 500 INTERNAL SERVER ERROR: If an unexpected error occurs.

        """
        try:
            serializer = ForgotPasswordSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.data.get('email')
                user = CustomUser.objects.get(email=email)
               
                # Generate OTP and save it in the UserOtherDetails model
                generated_otp = send_and_return_otp(email)
                user_details = UserOtherDetails.objects.get_or_create(user=user)[0]
                user_details.otp = generated_otp
                user_details.save()

                return Response(
                    {"message": "OTP has been sent to your registered email please check it",
                     "data": serializer.data},
                    status=status.HTTP_200_OK)
            messages = self.get_error_messages(serializer)
            return Response({"message": "Field error: "+", ".join(messages),
                            "data": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.error("Error during forgot password request: %s", error)
            return Response({"message": "Internal Server Error"},
                            status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordApiView(APIView, MessageError):
    """
    API endpoint for resetting user password.

    This endpoint allows users to reset their password by providing their email,
    new password, and OTP (One-Time Password) for verification.

    Request data should include:
    - email
    - new_password
    - otp

    Returns:
    - HTTP 200 OK: If password is reset successfully.
    - HTTP 400 BAD REQUEST: If request data is invalid, OTP is invalid, or user does not exist.

    """
    def get(self, request, format=None):
        """
        Method to handle GET request for initializing password reset.

        Returns:
        - HTTP 200 OK: If initial data is fetched successfully.

        """
        serializer = ResetPasswordSerializer()
        return Response(serializer.data)

    def post(self, request):
        """
        Method to handle POST request for resetting password.

        Returns:
        - HTTP 200 OK: If password is reset successfully.
        - HTTP 400 BAD REQUEST: If request data is invalid, OTP is invalid, or user does not exist.

        """
        try:
            serializer = ResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.data.get('email')
                user = CustomUser.objects.get(email=email)
                new_password = serializer.data.get('new_password')
                otp = serializer.data.get('otp')
                # breakpoint()
                if user.details.verify_otp(otp):
                    msg = "Your Password Updated Successfully."
                    user.set_password(new_password)
                    user.save()
                    return Response({"message": msg,
                                    "data": serializer.data},
                                    status=status.HTTP_200_OK)
                return Response({"message": "Invalid OTP",
                                "data": serializer.data},
                                status=status.HTTP_400_BAD_REQUEST)

            messages = self.get_error_messages(serializer)
            return Response({"message": "Field error: "+", ".join(messages),
                            "data": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.error("Error during rest password request: %s", error)
            return Response({"message": "Internal Server Error"},
                            status=status.HTTP_400_BAD_REQUEST)

class ProfileUpdateAPIView(APIView):
    """
    API endpoint for updating user profile."""
    def put(self, request):
        user = request.user  # Assuming user is authenticated

        # Serialize data for CustomUser model
        user_serializer = CustomUserSerializer(user, data=request.data)
        if not user_serializer.is_valid():
            # logger.error("Error during user profile updation: %s",user_serializer.error)
            return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user_serializer.save()

        # Serialize data for UserOtherDetails model
        user_details = user.details  # Assuming user has a related UserOtherDetails instance
        details_serializer = UserOtherDetailsUpdateSerializer(user_details, data=request.data.get('details'))
        if not details_serializer.is_valid():
            # logger.error("Error during user details updation: %s", details_serializer.errors)

            return Response(details_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        details_serializer.save()

        return Response({"message": "Profile updated successfully"}, status=status.HTTP_200_OK)