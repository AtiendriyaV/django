# Generated by Django 5.0.4 on 2024-05-07 12:58

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0026_alter_userprofile_otp_secret"),
    ]

    operations = [
        migrations.AlterField(
            model_name="userprofile",
            name="otp_secret",
            field=models.CharField(max_length=16),
        ),
    ]
