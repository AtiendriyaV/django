# Generated by Django 5.0.4 on 2024-05-07 15:07

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0031_uploadedfile"),
    ]

    operations = [
        migrations.CreateModel(
            name="FileData",
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
                ("S_NO", models.IntegerField()),
                ("Date", models.DateField()),
                ("Batch", models.CharField(max_length=50)),
                ("URL", models.URLField()),
                ("Vulnerabilities", models.TextField()),
                ("Critical", models.IntegerField()),
                ("High", models.IntegerField()),
                ("Medium", models.IntegerField()),
                ("Low", models.IntegerField()),
                ("Total", models.IntegerField()),
                ("Ministry", models.CharField(max_length=100)),
                ("Patched_Status", models.CharField(max_length=20)),
            ],
        ),
    ]
