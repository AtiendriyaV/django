# Generated by Django 5.0.1 on 2024-03-06 11:01

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0017_addedurl"),
    ]

    operations = [
        migrations.CreateModel(
            name="FileUploadModel",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("file", models.FileField(upload_to="uploads/")),
                ("uploaded_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
