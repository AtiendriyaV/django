# Generated by Django 5.0.1 on 2024-02-28 08:07

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0007_mitem_details"),
    ]

    operations = [
        migrations.AlterField(
            model_name="mitem",
            name="details",
            field=models.JSONField(default=dict),
        ),
    ]
