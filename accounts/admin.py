from django.contrib import admin

from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User, Group
from django.contrib import admin
from django.contrib import messages
from posts.models import Post

class CustomUserAdmin(UserAdmin):
    actions = ['add_user', 'remove_user', 'add_group', 'remove_group', 'remove_post']

    
    def add_user(self, request, queryset):
        for obj in queryset:
            # Create a new user using the selected object's details
            new_user = User.objects.create_user(
                username=obj.username,
                password=obj.password,  # You might want to set a default password or generate one
                email=obj.email,
                # Add more fields as needed
            )

            messages.success(request, f"User '{obj.username}' added successfully.")
        
        # Redirect back to the change list view
        return super().response_add(request, queryset)

    add_user.short_description = "Add selected users"

    def remove_user(self, request, queryset):
        for obj in queryset:
            # Check if the user exists before attempting to delete
            try:
                user_to_remove = User.objects.get(username=obj.username)
                user_to_remove.delete()
                messages.success(request, f"User '{obj.username}' removed successfully.")
            except User.DoesNotExist:
                messages.error(request, f"User '{obj.username}' does not exist.")
        
        # Redirect back to the change list view
        return super().response_add(request, queryset)

    remove_user.short_description = "Remove selected users"

    def add_group(self, request, queryset):
        for obj in queryset:
            # Create a new group using the selected object's details
            new_group, created = Group.objects.get_or_create(name=obj.group_name)

            if created:
                messages.success(request, f"Group '{obj.group_name}' added successfully.")
            else:
                messages.warning(request, f"Group '{obj.group_name}' already exists.")

        # Redirect back to the change list view
        return super().response_add(request, queryset)

    add_group.short_description = "Add selected groups"

    def remove_group(self, request, queryset):
        for obj in queryset:
            # Check if the group exists before attempting to delete
            try:
                group_to_remove = Group.objects.get(name=obj.group_name)
                group_to_remove.delete()
                messages.success(request, f"Group '{obj.group_name}' removed successfully.")
            except Group.DoesNotExist:
                messages.error(request, f"Group '{obj.group_name}' does not exist.")

        # Redirect back to the change list view
        return super().response_add(request, queryset)

    remove_group.short_description = "Remove selected groups"

# Unregister the default UserAdmin
admin.site.unregister(User)

# Register the User model with the custom UserAdmin
admin.site.register(User, CustomUserAdmin)


from django.contrib import messages
from django.contrib.auth.models import Group
from django.contrib.auth.admin import GroupAdmin
from django.contrib import admin
from django.db import models
from posts.models import Post
class CustomGroup(Group):
    class Meta:
        proxy = True

class CustomGroupAdmin(GroupAdmin):
    actions = ['remove_post']
    def remove_post(self, request, queryset):
        for post in queryset:
            try:
                # Assuming 'title' is a unique field for your Post model
                post_to_remove = Post.objects.get(title=post.title)
                post_to_remove.delete()
                messages.success(request, f"Post '{post.title}' removed successfully.")
            except Post.DoesNotExist:
                messages.error(request, f"Post '{post.title}' does not exist.")

        # Redirect back to the change list view
        return super().response_add(request, queryset)

    remove_post.short_description = "Remove selected posts"

# Register the CustomGroup model with the custom GroupAdmin
admin.site.register(CustomGroup, CustomGroupAdmin)

# Register other models with their respective admin classes
admin.site.register(Post)


