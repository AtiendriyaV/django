# Generated by Django 5.0.4 on 2024-05-09 16:24

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0033_work_delete_filedata"),
    ]

    operations = [
        migrations.RenameField(
            model_name="work",
            old_name="PatchedStatus",
            new_name="Patched_Status",
        ),
    ]