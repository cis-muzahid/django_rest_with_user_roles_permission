import random
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin)
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import Group, Permission
from user.managers import CustomUserManager
from django.utils import timezone
from datetime import datetime

from rest_framework_simplejwt.tokens import RefreshToken

GENDER_CHOICES = [
    ('M', 'Male'),
    ('F', 'Female'),
    ('O', 'Other')
]

# lets us explicitly set upload path and filename
def upload_to(instance, filename):
    return 'images/{filename}'.format(filename=filename)


class TimeStampedModel(models.Model):
    """TimeStampedModel model for created and modified date."""

    created_date = models.DateTimeField(auto_now_add=True, null=True)
    modified_date = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        """Meta class."""

        abstract = True


class CustomUser(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    """Using email instead of username."""

    PROVIDER = ( 
        ("Manual", "manual"),
        ("Google", "google"),
    )

    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=60, null=True, blank=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)
    is_email_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    groups = models.ManyToManyField(Group, verbose_name=_('groups'),
                                    blank=True, related_name='customuser_set')
    user_permissions = models.ManyToManyField(Permission,
                                              verbose_name=_(
                                                  'user permissions'),
                                              blank=True,
                                              related_name='customuser_set')
    authentication_provider = models.CharField(max_length=20, choices=PROVIDER,
                                               default="Manual")
    USERNAME_FIELD = 'email'
    objects = CustomUserManager()

    def __str__(self):
        """Str method to return ContactInfo name."""
        return '{}- {}- {}'.format(self.email, self.username, self.id)

    def save(self, *args, **kwargs):
        if 'pbkdf2_sha256' not in self.password:
            self.set_password(self.password)

        return super(CustomUser, self).save(*args, **kwargs)


class UserOtherDetails(TimeStampedModel):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE,
                                related_name='details', null=True, blank=True)
    first_name = models.CharField(max_length=60, null=True, blank=True)
    last_name = models.CharField(max_length=60, null=True, blank=True)
    phone = models.CharField(_('phone number'),
                             max_length=17, unique=True)
    is_phone_verified = models.BooleanField(default=False)
    address = models.CharField(('address'), max_length=500, blank=True,
                               null=True)
    profile_picture = models.ImageField(_('User photograph'),
                                        upload_to=upload_to, null=True,
                                        blank=True)

    dob = models.DateField(_('Date Of Birth'), null=True)
    gender = models.CharField(_('Gender'), max_length=3,
                              choices=GENDER_CHOICES, null=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_is_active = models.BooleanField(default=False)
    otp_timestamp = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    def _get_full_name(self):
        return "%s %s" % (self.first_name, self.last_name)

    def _set_full_name(self, combined_name):
        self.first_name, self.last_name = combined_name.split(' ', 1)

    def generate_otp(self):
        otp = ''.join(random.choices('0123456789', k=6))
        print(otp)
        self.otp = otp
        self.otp_timestamp = datetime.now()
        self.save()
        return self.otp

    def verify_otp(self, otp):
        if self.otp:
            if int(self.otp) == int(otp):
                self.otp = None
                self.otp_timestamp = None
                self.save()
                return True
        return False

    full_name = property(_get_full_name)

    @property
    def get_gender(self):
        gender = None
        for g in GENDER_CHOICES:
            if g[0] == self.gender:
                gender = g[1]
                break
        return gender

class TokenRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expiration_time = models.DateTimeField()

    def __str__(self):
        return self.user.email