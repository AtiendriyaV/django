from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.contrib.auth.models import User
from datetime import datetime, timedelta
import pyotp
from .forms import YourLoginForm
from .utils import send_otp
from .utils import generate_otp_secret
from django.urls import reverse_lazy
from . import forms
from accounts.models import UserProfile
from django.urls import reverse
from .models import User
from .forms import UserCreateForm  # Make sure to import your form
from django.views.generic import CreateView
from django.contrib.auth.decorators import login_required


class SignUp(CreateView):
    form_class = forms.UserCreateForm
    template_name = "accounts/signup.html"
    success_url = reverse_lazy("accounts:login")

@login_required
def logout_view(request):
    if request.method == "POST":
        logout(request)
        return redirect("accounts:login")
    return render(request, "accounts/logout.html", {})

from django.http import JsonResponse














class login_view(View):
    template_name = 'accounts/login.html'

    def get(self, request):
        form = YourLoginForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = YourLoginForm(request.POST)
        error_message = None

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user = authenticate(request, username=username, password=password)

            if user is not None:
                if user.is_superuser or user.groups.filter(name='Administrators').exists():
                    return redirect(reverse('admin:index'))
                else:
                    # If user is authenticated, generate OTP secret and initiate OTP sending
                    otp_secret = generate_otp_secret()
                    request.session['otp_secret_key'] = otp_secret
                    request.session['otp_valid_date'] = (datetime.now() + timedelta(minutes=1)).isoformat()
                    request.session['username'] = username

                    # Send OTP to the user
                    send_otp(request, user)

                    # Save the OTP secret to the UserProfile
                    user_profile, _ = UserProfile.objects.get_or_create(user=user)
                    user_profile.otp_secret = otp_secret
                    user_profile.save()
                return redirect("accounts:loginotp")
            else:
                error_message = 'Invalid username or password'

        return render(request, self.template_name, {'form': form, 'error_message': error_message})


from django.views import View
from django.contrib.auth import login
from django.urls import reverse
from datetime import datetime, timedelta
import pyotp
from accounts.models import UserProfile

class otp_view(View):
    template_name = 'accounts/loginotp.html'

    def get(self, request):
        return render(request, self.template_name, {})

    def post(self, request):
        print("Starting OTP verification...")
        otp = request.POST.get('otp')
        username = request.session.get('username')
        otp_secret_key = request.session.get('otp_secret_key', None)
        request.session['otp_valid_date'] = (datetime.now() + timedelta(minutes=5)).isoformat()
        otp_valid_date = request.session.get('otp_valid_date')
        print("otp_secret_key:", otp_secret_key)
        print("otp_valid_date:", otp_valid_date)
        print("username:", username)
        error_messages = None

        if 'resend_otp' in request.POST:
            # Resend OTP logic
            if username and otp_secret_key:
                user = get_object_or_404(User, username=username)
                send_otp(request, user)  # Ensure this function sends OTP
                print("OTP Resent successfully")
                return redirect(request.path_info)  # Redirect to the same page
            else:
                error_messages = "Invalid session data for resending OTP"
        else:
            if username and otp_secret_key and otp_valid_date:
                valid_until = datetime.fromisoformat(otp_valid_date)
                print(f"Current time: {datetime.now()}")
                print(f"Valid until: {valid_until}")

                if valid_until > datetime.now():
                    totp = pyotp.TOTP(otp_secret_key, interval=60)

                    if totp.verify(otp):
                        user = get_object_or_404(User, username=username)
                        user_profile = UserProfile.objects.get(user=user)
                        user_profile.otp_completed = True
                        user_profile.save()
                        print("verifyotp")
                        login(request, user)

                        del request.session['otp_secret_key']
                        del request.session['otp_valid_date']
                        del request.session['username']

                        # Check if the user is an administrator
                        if user.is_superuser:
                            print("Redirecting to admin:index")
                            return redirect(reverse('admin:index'))
                        else:
                            print("Redirecting to well")
                            return redirect("well")
                    else:
                        error_messages = "Invalid OTP"
                else:
                    error_messages = "OTP expired"
            else:
                error_messages = "Invalid session data"

        print("Error messages:", error_messages)
        return render(request, self.template_name, {'error_messages': error_messages})




    
from django.views import View
from accounts.models import UserProfile
from django.utils.decorators import method_decorator

@method_decorator(login_required, name='dispatch')

class WellView(View):
    template_name = 'well.html'

    def get(self, request):
        print("Inside WellView")
        if request.user.is_authenticated:
            print("User is authenticated")
            user_profile = None
            try:
                user_profile = UserProfile.objects.get(user=request.user)
                print(f"UserProfile found: {user_profile}")
            except UserProfile.DoesNotExist:
                print("UserProfile not found for the user")

            context = {'user': request.user, 'user_profile': user_profile}
            return render(request, self.template_name, context)
        else:
            print("User is not authenticated")
            return redirect("accounts:login")

class adminView(View):
    template_name = 'admin.html'

from .models import MItem, AddItemForm
from django.contrib.auth.decorators import login_required
from accounts.models import MItem
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError


from .models import MItem , AddItemForm
from django.contrib.auth.decorators import login_required

from django import forms
from .models import UserProfile
validators = URLValidator()

@login_required
def add_item(request):
    try:
        user_profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        user_profile = None

    if user_profile and user_profile.otp_completed:
        if request.method == 'POST':
            form = AddItemForm(request.POST)
            if form.is_valid():
                new_item_name = form.cleaned_data['new_item']
                # Create a new MItem instance and associate it with the current user
                new_item = MItem.objects.create(name=new_item_name, user=request.user)
                return redirect('well')  # Redirect to appropriate view after adding
        else:
            form = AddItemForm()

        # Retrieve all items including new ones
        all_items = MItem.objects.all()

        return render(request, 'add_item.html', {'form': form, 'user_profile': user_profile, 'all_items': all_items})
    else:
        return redirect('loginotp')


class AddItemForm(forms.Form):
    new_item = forms.CharField(label='New Item', max_length=100)


# views.py
from django.shortcuts import redirect, get_object_or_404
from .models import MItem

def delete_item(request, item_id):
    item = get_object_or_404(MItem, pk=item_id)
    if request.method == 'POST':
        item.delete()
    return redirect('well')  # Redirect to the appropriate page after deletion





from django.http import JsonResponse
from .models import MItem

def get_latest_items(request):
    latest_items = list(MItem.objects.values('id', 'name'))  # Query the latest items
    return JsonResponse({'latest_items': latest_items})


from django.shortcuts import render
from .models import MItem
# views.py

from django.shortcuts import render
from .models import AddedItem

def some_view(request):
    added_items = AddedItem.objects.all()  # Retrieve added items from the database
    return render(request, 'well', {'added_items': added_items})


from django.shortcuts import render
from .models import MItem


def item_table_view(request):
    items = MItem.objects.all()
    return render(request, 'item_table.html', {'items': items})



from django.http import JsonResponse
from .models import MItem

def item_list_endpoint(request):
    items = MItem.objects.all().values('name', 'user__username')  # Access the username through the user field
    return JsonResponse(list(items), safe=False)


from django.contrib import messages
from .forms import UsageForm
from .models import MItem
from django.http import JsonResponse

from django.contrib import messages
from .forms import UsageForm
from .models import MItem
from django.contrib.auth.decorators import login_required

from django.http import JsonResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import MItem  # Import your item model
from .forms import UsageForm  # Import your form
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from .models import MItem
from .forms import UsageForm

@login_required
def process_usage_form(request):
    user_profile = getattr(request.user, 'userprofile', None)
    if user_profile and user_profile.otp_completed:
        items = MItem.objects.all()

        if request.method == 'POST':
            form = UsageForm(request.POST)
            if form.is_valid():
                added_item_id = form.cleaned_data['added_item']
                usage = form.cleaned_data['usage']
                navigation_url = form.cleaned_data['navigation_url']

                try:
                    added_item = MItem.objects.get(id=added_item_id)
                except MItem.DoesNotExist:
                    messages.error(request, 'The selected item does not exist.')
                    return redirect('error')

                if usage == 'navigation':
                    added_item.details = {
                        'usage': 'navigation',
                        'navigation_url': navigation_url
                    }
                    added_item.save()
                    messages.success(request, 'Item details updated successfully.')
                    return JsonResponse({'success': True})
                else:
                    messages.error(request, 'Invalid usage.')
                    return JsonResponse({'success': False, 'error': 'Invalid usage'})
            else:
                return JsonResponse({'success': False, 'error': form.errors})
        else:
            form = UsageForm()

        return render(request, 'process_usage_form.html', {'form': form, 'items': items, 'user_profile': user_profile})
    else:
        return redirect('accounts:loginotp')

def navigate_to_url(request, item_id):
    try:
        item = MItem.objects.get(id=item_id)
        if item.details and 'navigation_url' in item.details:
            navigation_url = item.details['navigation_url']
            if navigation_url.startswith('http://') or navigation_url.startswith('https://'):
                return redirect(navigation_url)
            else:
                return HttpResponse('Invalid URL format.')
        else:
            return HttpResponse('Navigation URL not found for this item.')
    except MItem.DoesNotExist:
        return HttpResponse('Item not found.')


from django.urls import path
from django.http import HttpResponse

def favicon_view(request):
    return HttpResponse(status=404)

# upload_file view
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from .models import UserProfile, FileUploadModel
from pandas import read_excel
import io

from django.contrib.auth.decorators import login_required
from .models import FileUploadModel
from .forms import UploadFileForm
import pandas as pd
from django.contrib.auth.decorators import login_required
from .models import FileUploadModel
from .forms import UploadFileForm
from django.contrib.auth.decorators import login_required
from .models import FileUploadModel
from .forms import UploadFileForm
import pandas as pd
import pandas as pd
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import UploadFileForm
from .models import FileUploadModel
import pandas as pd

@login_required
def upload_file(request):
    user_profile = getattr(request.user, 'userprofile', None)
    if user_profile and user_profile.otp_completed:
        if request.method == 'POST':
            form = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = request.FILES['file']
                # Save the uploaded file to the database
                file_object = FileUploadModel(file=uploaded_file)
                file_object.save()
                # Redirect or return JSON response if needed
                return redirect('accounts:Data')  # Redirect to view to display uploaded data
        else:
            form = UploadFileForm()
        return render(request, 'upload_file.html', {'form': form, 'user_profile': user_profile})
    else:
        return redirect('well')  # Redirect to your login page or any other page
    
from .models import FileUploadModel, ExcelData
from pandas import read_excel, read_csv
from pandas.errors import EmptyDataError
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import UploadFileForm
import io


from .models import UploadedFile  # Import the UploadedFile model
from .models import UploadedFile  # Import the UploadedFile model
import pymysql  # Import the MySQL connector
from .models import UserProfile, FileUploadModel
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import pandas as pd
import io





from .models import UserProfile, FileUploadModel
import pandas as pd
import io
import pymysql
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from pandas.errors import EmptyDataError
from .models import UserProfile, FileUploadModel
import pandas as pd
import io
import pymysql
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from pandas.errors import EmptyDataError

from .models import UserProfile, FileUploadModel
import pandas as pd
import io
import pymysql
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from pandas.errors import EmptyDataError
from datetime import datetime





import pymysql
import pandas as pd
import io
from django.shortcuts import render, redirect
from .models import UserProfile, FileUploadModel
from django.contrib.auth.decorators import login_required
from pandas.errors import EmptyDataError
from datetime import datetime

from .models import UploadedFile
import pymysql
import pandas as pd
from datetime import datetime
import io

@login_required
def Data(request):
    try:
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)
        print("Debugging Data view - User Profile:", user_profile)

        if user_profile and user_profile.otp_completed:
            # Fetch the uploaded file from the database
            uploaded_file = FileUploadModel.objects.last()
            print("Debugging Data view - Uploaded File:", uploaded_file)
            if uploaded_file:
                # Read file data from the database
                file_data = uploaded_file.file.read()

                # Determine file type (CSV or Excel) and process accordingly
                if uploaded_file.file.name.endswith('.csv'):
                    # Read CSV file data into a pandas DataFrame
                    df = pd.read_csv(io.StringIO(file_data.decode('utf-8')))
                elif uploaded_file.file.name.endswith('.xlsx'):
                    # Read Excel file data into a pandas DataFrame
                    df = pd.read_excel(io.BytesIO(file_data))
                else:
                    return render(request, 'Data.html', {'error': 'Unsupported file format', 'user_profile': user_profile})

                print("Debugging Data view - DataFrame Loaded Successfully")

                # Convert DataFrame to list of dictionaries
                data_list = df.to_dict(orient='records')

                # Convert date column to the desired format
                for item in data_list:
                    item['Date'] = datetime.strptime(item['Date'], '%d-%m-%Y').strftime('%Y-%m-%d')

                # Establish a connection to MySQL
                connection = pymysql.connect(
                    host='localhost',
                    user='Admin',
                    password='Asdf@1234',
                    database='work'
                )

                # Insert data into MySQL table
                with connection.cursor() as cursor:
                    for item in data_list:
                        # Convert 'High' column to string and replace newline characters with commas
                        high_values = ','.join(str(val) for val in item['High'].split('\n'))
                        sql = "INSERT INTO work (Date, Batch, URL, Vulnerabilities, Critical, High, Medium, Low, Total, Ministry, Patched_Status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                        cursor.execute(sql, (
                            item['Date'],
                            item['Batch'],
                            item['URL'],
                            item['Vulnerabilities'],
                            item['Critical'],
                            high_values,
                            item['Medium'],
                            item['Low'],
                            item['Total'],
                            item['Ministry'],
                            item['Patched_Status']
                        ))

                connection.commit()
                connection.close()

                return render(request, 'Data.html', {'data_list': data_list, 'user_profile': user_profile})
            else:
                return redirect('accounts:upload_file')
        else:
            return render(request, 'Data.html', {'error': 'OTP not completed or UserProfile not found', 'user_profile': user_profile})
    except FileNotFoundError:
        return redirect('accounts:upload_file')
    except EmptyDataError:
        return render(request, 'Data.html', {'error': 'No columns to parse from file', 'user_profile': user_profile})













from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import UserProfile

@login_required
def chart(request):
    # Retrieve or create the user's profile
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)

    print("Debugging: User Profile -", user_profile)  # Print user profile for debugging

    # Check if the user has completed OTP verification
    if user_profile.otp_completed:
        # Handle POST request
        if request.method == 'POST':
            # Logic for handling POST request if needed
            pass
            
        # Sample data and labels for the chart
        data = [10, 20, 30, 40, 50]
        labels = ['January', 'February', 'March', 'April', 'May']

        return render(request, 'chart.html', {'data': data, 'labels': labels, 'user_profile': user_profile})

    else:
        # Handle the case where OTP verification is not completed
        print("Debugging: OTP verification not completed")
        return render(request, 'login')
