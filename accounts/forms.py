from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.forms import Form

class UserCreateForm(UserCreationForm):
    class Meta:
        fields = ("username", "email", "password1", "password2")
        model = get_user_model()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].label = "Display name"
        self.fields["email"].label = "Email address"

# forms.py
from django import forms

class YourLoginForm(forms.Form):
    username = forms.CharField(label='Username')
    password = forms.CharField(label='Password', widget=forms.PasswordInput())


# forms.py
from django import forms
from .models import CustomNavigationItem

class CustomNavigationItemForm(forms.ModelForm):
    class Meta:
        model = CustomNavigationItem
        fields = ['label', 'url']

class AddItemForm(forms.Form):
    new_item = forms.CharField(label='New Item', max_length=100)
    added_item = forms.CharField(max_length=100)
    dropdown_count = forms.IntegerField(label='Number of dropdown options', min_value=1, required=False)
    navigation_url = forms.URLField(label='Navigation URL', required=False)



from django import forms

class UsageForm(forms.Form):
    added_item = forms.CharField(max_length=100)
    usage = forms.ChoiceField(choices=[('navigation', 'Navigation')], label='Usage')
    navigation_url = forms.URLField(label='Navigation URL')

from django import forms

class UploadFileForm(forms.Form):
    file = forms.FileField()
