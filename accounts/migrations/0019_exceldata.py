# Generated by Django 5.0.1 on 2024-03-06 17:51

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0018_fileuploadmodel"),
    ]

    operations = [
        migrations.CreateModel(
            name="ExcelData",
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
                ("name", models.CharField(max_length=100)),
                ("date_modified", models.DateTimeField()),
            ],
        ),
    ]
