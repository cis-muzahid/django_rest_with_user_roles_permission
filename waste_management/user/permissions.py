from rest_framework import permissions
from rest_framework_simplejwt.token_blacklist.models import (OutstandingToken,
                                                             BlacklistedToken)
from user.validation import CustomValidation


class RefreshTokenPermission(permissions.BasePermission):
    """
    Global permission check
    """
    message = 'Refresh token has already blacklisted'

    def has_permission(self, request, view):
        _ = self.message
        if request.META.get('HTTP_USER_REFRESH_TOKEN', None):
            outstanding = OutstandingToken.objects.filter(
                token=request.META['HTTP_USER_REFRESH_TOKEN']).last()
            if outstanding:
                if BlacklistedToken.objects.filter(token_id=outstanding.id).exists():
                    raise CustomValidation(detail=_, field='detail',
                                           status_code=400)
            return bool(request.user and request.user.is_authenticated)
        raise CustomValidation(
            detail='You have to pass Refresh Token in Headers',
            field='detail',
            status_code=400)
        # raise CustomValidation(
        #     detail='You dont have permission to perform this action.',
        #     field='detail',
        #     status_code=400)