from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect , get_object_or_404
from django.contrib import messages
from django.views import generic
from django.urls import reverse
from accounts.models import UserProfile
from .models import Group
from accounts.utils import get_user_profile
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from accounts.models import UserProfile  # Import UserProfile from accounts.models

@login_required
def group(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)

        # Check if OTP is completed and update it if needed
        if not user_profile.otp_completed:
            # Add your logic for OTP completion
            user_profile.otp_completed = True
            user_profile.save()

        print(f"user: {request.user}, user_profile: {user_profile}, otp_completed: {user_profile.otp_completed}")

        # Pass 'user' and 'user_profile' to the template
        return render(request, 'groups/group_base.html', context={'user': request.user, 'user_profile': user_profile})
    except UserProfile.DoesNotExist:
        # Handle the case where the UserProfile does not exist for the user
        messages.warning(request, "UserProfile does not exist for the current user.")
        return redirect('create')  # Redirect to an appropriate view

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from groups.models import Group, GroupMember
from accounts.models import UserProfile
from django import forms  # Import forms module
from django.contrib import messages

@login_required
def create_group(request):
    user_profile = UserProfile.objects.get(user=request.user)

    # Check if OTP is completed and update it if needed
    if not user_profile.otp_completed:
        # Add your logic for OTP completion
        user_profile.otp_completed = True
        user_profile.save()

    # Define the form inline
    class GroupCreateForm(forms.ModelForm):
        class Meta:
            model = Group
            fields = ["name", "description"]

    form = GroupCreateForm(request.POST or None)

    if form.is_valid():
        group = form.save(commit=False)
        group.save()

        # Use 'user' instead of 'user_profile'
        GroupMember.objects.create(group=group, user=user_profile.user)

        messages.success(request, "Group created successfully.")
        return redirect('groups:all')

    return render(request, 'groups/group_form.html', {'form': form, 'user': request.user, 'user_profile': user_profile})

from django.db.models import Count
from django.views import generic
from .models import Group
from accounts.models import UserProfile
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db.models import Count
from .models import Group
from accounts.models import UserProfile
# groups/views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from groups.models import Group
from accounts.models import UserProfile
from django.db.models import Count

# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count
from .models import Group
from accounts.models import UserProfile

@login_required
def list_groups(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        messages.warning(request, "UserProfile does not exist for the current user.")
        return redirect('login')  # Redirect to an appropriate view

    groups = Group.objects.annotate(member_count=Count('members'))
    return render(request, 'groups/group_list.html', {'groups': groups, 'user': request.user, 'user_profile': user_profile})

from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from groups.models import Group, GroupMember
from accounts.models import UserProfile
from django.contrib.auth.decorators import login_required

@login_required
def join_group(request, slug):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        messages.warning(request, "UserProfile does not exist for the current user.")
        return redirect('login')  # Redirect to an appropriate view

    group = get_object_or_404(Group, slug=slug)

    try:
        if user_profile.otp_completed:
            # Check if the user is already a member of the group
            if not GroupMember.objects.filter(group=group, user_profile=user_profile).exists():
                GroupMember.objects.create(user=request.user, group=group, user_profile=user_profile)
                messages.success(request, f"You have joined the {group.name} group.")
            else:
                messages.warning(request, f"You are already a member of the {group.name} group.")
        else:
            messages.warning(request, "You need to complete OTP verification to join groups.")
    except GroupMember.DoesNotExist:
        messages.warning(request, "You are not a member of this group.")

    return redirect('groups:single', slug=slug)

from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from groups.models import Group, GroupMember
from accounts.models import UserProfile
from django.contrib.auth.decorators import login_required

@login_required
def leave_group(request, slug):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        messages.warning(request, "UserProfile does not exist for the current user.")
        return redirect('group:single')  # Redirect to an appropriate view

    group = get_object_or_404(Group, slug=slug)

    try:
        membership = GroupMember.objects.filter(
            user=request.user,
            group__slug=slug
        ).get()

        if user_profile.otp_completed:
            if request.user in group.members.all():
                membership.delete()
                messages.success(request, f"You have successfully left the {group.name} group.")
            else:
                messages.warning(request, "You are not a member of this group.")
        else:
            messages.warning(request, "You need to complete OTP verification to leave groups.")

    except GroupMember.DoesNotExist:
        messages.warning(request, "You can't leave this group because you aren't in it.")

    return redirect('groups:single', slug=slug)


# views.py
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.views import generic
from groups.models import Group, GroupMember
from accounts.models import UserProfile
from django.contrib.auth.decorators import login_required

class SingleGroup(generic.DetailView):
    model = Group
    template_name = 'groups/group_detail.html'  # Corrected template path

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        group = context['object']

        try:
            user_profile = UserProfile.objects.get(user=self.request.user)
            context['user_profile'] = user_profile
        except UserProfile.DoesNotExist:
            messages.warning(self.request, "UserProfile does not exist for the current user.")
            # Redirect to an appropriate view or page if UserProfile is not found
            return redirect('all')  # Replace with the actual view name or URL

        context['members'] = group.members.all()
        return context

