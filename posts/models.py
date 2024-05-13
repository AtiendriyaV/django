# posts/models.py
from django.db import models
from django.conf import settings
from django.urls import reverse
import misaka
from groups.models import Group
from django.contrib.auth import get_user_model
from django.db import models
from django.contrib.auth.models import User  # Import the User model if needed

User = get_user_model()

class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, default=None)
    message = models.CharField(max_length=1000)   
    created_at = models.DateTimeField(auto_now_add=True)
    message_html = models.CharField(editable=False, default='',max_length=1000) 

    def __str__(self):
        return f'{self.user.username} - {self.created_at}'

    def save(self, *args, **kwargs):
        self.message_html = misaka.html(self.message)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('posts:single', kwargs={'username': self.user.username, 'pk': self.pk})

    class Meta:
        unique_together = ['user', 'message',]


    @property
    def is_authenticated_and_otp_completed(self):
        # Assuming user has a related UserProfile model with an 'otp_completed' field
        if hasattr(self.user, 'user_profile'):
            return self.user.is_authenticated and self.user.user_profile.otp_completed
        return False


from django.db import models
from django.contrib.auth import get_user_model
from groups.models import Group

User = get_user_model()

class OldGroupPost(models.Model):

    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    message = models.CharField(max_length=1000)  
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.author.username} - {self.created_at}"
