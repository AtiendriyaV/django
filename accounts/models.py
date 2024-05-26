# accounts/models.py

from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.dispatch import receiver
from django.db.models.signals import post_save
import pyotp

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)

        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(username, email, password, **extra_fields)

    def create_user(self, username, email, password=None, **extra_fields):  
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True, default='')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    groups = models.ManyToManyField('auth.Group', related_name='custom_user_set', blank=True)
    user_permissions = models.ManyToManyField('auth.Permission', related_name='custom_user_set', blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return "@{}".format(self.username)

# accounts/models.py
from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp_completed = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=100) 
    

    def generate_otp_secret(self):
         return pyotp.random_base32()

    def save(self, *args, **kwargs):
        if not self.otp_secret:
            self.otp_secret = self.generate_otp_secret()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.user.username
# models.py



from django.contrib.postgres.fields import JSONField
from django.db import models
from django.contrib.auth.models import User

from django.db import models
from django.contrib.auth.models import User
import json
# models.py
import json
from django.db import models
from django.contrib.auth.models import User


class MItem(models.Model):
    name = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=None)
    details = models.TextField(default='{}')  # Store JSON data as a string

    def get_details(self):
        try:
            return json.loads(self.details)
        except json.JSONDecodeError:
            return {}

    def set_details(self, value):
        self.details = json.dumps(value)

    def __str__(self):
        return f"{self.name} - {self.user.username}"


class CustomNavigationItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    label = models.CharField(max_length=100)
    url = models.URLField()
    href = models.URLField(default='') 

    def __str__(self):
        return self.label


class AddItemForm(models.Model):
    name = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    model = MItem
    fields = ['name', 'href']
    
    def __str__(self):
        return self.name


class AddedItem(models.Model):
    name = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    href = models.URLField(default='')  # Add URL field to store the URL for the added item

    def __str__(self):
        return self.name
    
    from django.db import models

class AddedURL(models.Model):
    name = models.CharField(max_length=100)
    url = models.URLField()

from django.contrib.auth.models import User

class FileUploadModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)  
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.file.name

from django.db import models

class ExcelData(models.Model):
    name = models.CharField(max_length=100)
    date_modified = models.DateTimeField()

    def __str__(self):
        return self.name
    

class Data(models.Model):
    S_NO = models.IntegerField()
    Date = models.DateField()
    Batch = models.CharField(max_length=50)
    URL = models.URLField()
    Vulnerabilities = models.TextField()
    Critical = models.IntegerField()
    High = models.BigIntegerField()  # Change here
    Medium = models.IntegerField()
    Low = models.IntegerField()
    Total = models.IntegerField()
    Ministry = models.CharField(max_length=200)  # Change here
    Patched_Status = models.CharField(max_length=50)  # Change heres

    def __str__(self):
        return f"{self.S_NO} - {self.Date} - {self.Batch}"
    
from django.db import models

class UploadedFile(models.Model):
    file_data = models.BinaryField()
    uploaded_at = models.DateTimeField(auto_now_add=True)


class Work(models.Model):
    S_NO = models.IntegerField(primary_key=True)
    Date = models.DateField()
    Batch = models.CharField(max_length=50)
    URL = models.URLField(max_length=200)
    Vulnerabilities = models.TextField()
    Critical = models.IntegerField()
    High = models.BigIntegerField()  # Change here
    Medium = models.IntegerField()
    Low = models.IntegerField()
    Total = models.IntegerField()
    Ministry = models.CharField(max_length=100)
    Patched_Status = models.CharField(max_length=20)


