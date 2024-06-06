from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.contrib.auth.models import User
from datetime import datetime, timedelta
import pyotp
from .models import MItem, AddItemForm, UserProfile  # Make sure to import MItem and AddItemForm
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from .forms import YourLoginForm, UserCreateForm  # Make sure to import YourLoginForm and UserCreateForm
from .utils import send_otp, generate_otp_secret
from django.urls import reverse_lazy, reverse
from django.views.generic import CreateView
from .forms import UserCreateForm
from . import forms

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
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required


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

import pandas as pd
from django.shortcuts import render, redirect
from .models import FileUploadModel, UserProfile
from django.contrib.auth.decorators import login_required
from django.db import connection, IntegrityError
from django.shortcuts import render, redirect
from .models import FileUploadModel, UserProfile
from django.contrib.auth.decorators import login_required
import pandas as pd
import os
from .forms import UploadFileForm


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import UploadFileForm
from .models import FileUploadModel, UserProfile

@login_required
def upload_file(request):
    user_profile = getattr(request.user, 'userprofile', None)
    if user_profile and user_profile.otp_completed:
        if request.method == 'POST':
            form = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = request.FILES['file']
                # Save the uploaded file to the database
                file_object = FileUploadModel(file=uploaded_file, user=request.user)
                file_object.save()
                # Redirect to Data view to display uploaded data
                return redirect('accounts:Data')
        else:
            form = UploadFileForm()
        return render(request, 'upload_file.html', {'form': form, 'user_profile': user_profile})
    else:
        return redirect('well')  # Redirect to your login page or any other page


import os
from django.shortcuts import render, redirect
from .models import FileUploadModel, UserProfile
from django.contrib.auth.decorators import login_required
import pandas as pd
from django.http import Http404

import os
from django.shortcuts import render, redirect
from .models import FileUploadModel, UserProfile
from django.contrib.auth.decorators import login_required
import pandas as pd
from django.http import Http404  # Assuming you have a utility function for database insertion


import os
from django.shortcuts import render, redirect
from .models import FileUploadModel, UserProfile
from django.contrib.auth.decorators import login_required
import pandas as pd
from django.http import Http404

@login_required
def Data(request):
    print("Entering Data view...")
    try:
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)
        print(f"UserProfile obtained: {user_profile}, Created: {created}")
        
        if user_profile and user_profile.otp_completed:
            print("User profile found and OTP completed.")
            uploaded_file = FileUploadModel.objects.filter(user=request.user).last()
            print(f"Uploaded file: {uploaded_file}")

            if uploaded_file:
                file_path = uploaded_file.file.path
                if os.path.exists(file_path):
                    file_extension = uploaded_file.file.name.split('.')[-1].lower()
                    print(f"File extension: {file_extension}")

                    try:
                        if file_extension in ['xlsx', 'xls']:
                            engine = 'openpyxl' if file_extension == 'xlsx' else 'xlrd'
                            df = pd.read_excel(uploaded_file.file, engine=engine)
                        elif file_extension == 'csv':
                            df = pd.read_csv(uploaded_file.file)
                        else:
                            print("Unsupported file format")
                            return render(request, 'Data.html', {'error': 'Unsupported file format', 'user_profile': user_profile})
                        
                        if df.empty:
                            print("The uploaded file is empty")
                            return render(request, 'Data.html', {'error': 'The uploaded file is empty', 'user_profile': user_profile})

                        # Convert date column to the correct format
                        if 'Date' in df.columns:
                            df['Date'] = pd.to_datetime(df['Date'], format='%d-%m-%Y').dt.strftime('%Y-%m-%d')

                        # Insert Serial Number
                        df.insert(0, 'S_no', range(1, len(df) + 1))

                        # Replace newline characters with <br> tags in specified columns
                        for col in ['Vulnerabilities', 'Critical', 'High', 'Medium', 'Low', 'Total', 'Ministry']:
                            if col in df.columns:
                                df[col] = df[col].replace('\n', '<br>', regex=True)

                        # Process 'Patched_Status' column if it exists
                        if 'Patched_Status' in df.columns:
                            df['Patched_Status'] = df['Patched_Status'].apply(lambda x: "<br>".join(x.split("\n")))
                        else:
                            df['Patched_Status'] = ''

                        # Ensure 'Date', 'Batch', 'URL', and 'Ministry' columns exist and handle NaN values
                        for col in ['Date', 'Batch', 'URL', 'Ministry']:
                            if col not in df.columns:
                                df[col] = ''
                            df[col] = df[col].fillna('')

                        data_list = df.to_dict(orient='records')
                        insert_data_into_db(data_list)
                          # Insert data into the respective tables
                        insert_data_into_respective_tables(data_list)

                        return render(request, 'Data.html', {'data_list': data_list, 'user_profile': user_profile})

                    except Exception as e:
                        print(f"Error reading file: {e}")
                        return render(request, 'Data.html', {'error': f"Error reading the file: {e}", 'user_profile': user_profile})
                else:
                    print("File does not exist. Redirecting to upload_file.")
                    return redirect('accounts:upload_file')
            else:
                print("No uploaded file found for the user.")
                return redirect('accounts:upload_file')
        else:
            print("OTP not completed or UserProfile not found.")
            return render(request, 'Data.html', {'error': 'OTP not completed or UserProfile not found', 'user_profile': user_profile})
    except FileNotFoundError:
        print("FileNotFoundError: Redirecting to upload file.")
        return redirect('accounts:upload_file')
    except UserProfile.DoesNotExist:
        print("UserProfile.DoesNotExist: Creating new user profile.")
        user_profile = UserProfile.objects.create(user=request.user, otp_completed=False)
        return render(request, 'Data.html', {'error': 'User profile not found', 'user_profile': user_profile})
    except Exception as e:
        print(f"Error: {e}")
        return render(request, 'Data.html', {'error': str(e), 'user_profile': user_profile})


def insert_data_into_db(data_list):
    print("Inserting data into the database...")
    try:
        with connection.cursor() as cursor:
            for data in data_list:
                try:
                    print(f"Inserting row: {data}")
                    query = """
                        INSERT INTO joined_results (S_no, Date, Batch, URL, Ministry, Vulnerabilities, Critical, High, Medium, Low, Total, Patched_Status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    values = (
                        data.get('S_no'),
                        data.get('Date'),
                        data.get('Batch'),
                        data.get('URL'),
                        data.get('Ministry'),
                        data.get('Vulnerabilities', ''),
                        data.get('Critical', ''),
                        data.get('High', ''),
                        data.get('Medium', ''),
                        data.get('Low', ''),
                        data.get('Total', ''),
                        data.get('Patched_Status', '')
                    )
                    print(f"Executing query: {query} with values: {values}")
                    cursor.execute(query, values)
                except IntegrityError as ie:
                    print(f"IntegrityError: {ie}")
                except Exception as e:
                    print(f"Error inserting row: {e}")
        print("Data Inserted Successfully")
    except Exception as e:
        print(f"Error inserting data into DB: {e}")
 

from pymysql import IntegrityError

from pymysql import IntegrityError
from pymysql import IntegrityError

def insert_data_into_respective_tables(data_list):
    print("Inserting data into the respective tables...")
    try:
        with connection.cursor() as cursor:
            for data in data_list:
                try:
                    # Insert data into the 's_no' table
                    cursor.execute("INSERT INTO s_no (S_no) VALUES (NULL)")
                    s_no_id = cursor.lastrowid  # Get the auto-generated primary key value

                    # Truncate 'Vulnerabilities' data if it exceeds the maximum allowed length
                    vulnerabilities = data['Vulnerabilities'][:255]  # Adjust the length as per your schema

                    # Insert data into the 'date' table using the generated 's_no' value
                    cursor.execute("INSERT INTO date (s_no, date) VALUES (%s, %s)", (s_no_id, data['Date']))

                    # Insert data into the 'batch' table using the generated 's_no' value
                    cursor.execute("INSERT INTO batch (s_no, batch) VALUES (%s, %s)", (s_no_id, data['Batch']))

                    # Insert data into the 'url' table using the generated 's_no' value
                    cursor.execute("INSERT INTO url (s_no, url) VALUES (%s, %s)", (s_no_id, data['URL']))

                    # Insert truncated 'Vulnerabilities' data into the 'vulnerabilities' table using the generated 's_no' value
                    cursor.execute("INSERT INTO vulnerabilities (s_no, vulnerabilities) VALUES (%s, %s)", (s_no_id, vulnerabilities))

                    # Insert data into other tables in a similar manner

                    print("Row inserted successfully")

                except IntegrityError as ie:
                    if ie.args[0] == 1062:  # Duplicate entry error code
                        print(f"Duplicate entry error: {ie}")
                    else:
                        print(f"IntegrityError: {ie}")
                except Exception as e:
                    print(f"Error inserting row: {e}")

        print("Data Inserted Successfully")
    except Exception as e:
        print(f"Error inserting data into DB: {e}")





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



from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import UserProfile
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import UserProfile

@login_required
def audit_view(request):
    context = {}

    try:
        user_profile = UserProfile.objects.get(user=request.user)

        # Check if OTP is completed and update it if needed
        if not user_profile.otp_completed:
            # Add your logic for OTP completion
            user_profile.otp_completed = True
            user_profile.save()

        print(f"user: {request.user}, user_profile: {user_profile}, otp_completed: {user_profile.otp_completed}")
        context['user_profile'] = user_profile

    except UserProfile.DoesNotExist:
        print(f"No UserProfile found for user: {request.user}")
        context['error'] = "User profile not found"

    return render(request, 'accounts/audit.html', context)


@login_required
def review_view(request):
    context = {}

    try:
        user_profile = UserProfile.objects.get(user=request.user)

        # Check if OTP is completed and update it if needed
        if not user_profile.otp_completed:
            # Add your logic for OTP completion
            user_profile.otp_completed = True
            user_profile.save()

        print(f"user: {request.user}, user_profile: {user_profile}, otp_completed: {user_profile.otp_completed}")
        context['user_profile'] = user_profile

    except UserProfile.DoesNotExist:
        print(f"No UserProfile found for user: {request.user}")
        context['error'] = "User profile not found"

    return render(request, 'accounts/review.html', context)

# # views.py
from formtools.wizard.views import SessionWizardView
from django.shortcuts import render, redirect
from .forms import FormStepOne, FormStepTwo
from .models import UserProfile
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

FORMS = [
    ("step_one", FormStepOne),
    ("step_two", FormStepTwo),
]

TEMPLATES = {
    "step_one": "form_step_one.html",
    "step_two": "form_step_two.html",
}

@method_decorator(login_required, name='dispatch')
class MyWizardView(SessionWizardView):
    form_list = FORMS

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)
        
        if not user_profile.otp_completed:
            return render(request, 'otp_not_completed.html')
        
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, form, **kwargs):
        context = super().get_context_data(form, **kwargs)
        context['user_profile'] = UserProfile.objects.get(user=self.request.user)
        return context

    def get_template_names(self):
        return [TEMPLATES[self.steps.current]]

    def done(self, form_list, **kwargs):
        form_data = [form.cleaned_data for form in form_list]
        return render(self.request, 'formdone.html', {
            'form_data': form_data
        })
