# Generated by Django 5.0.4 on 2024-05-08 16:10

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0032_filedata"),
    ]

    operations = [
        migrations.CreateModel(
            name="Work",
            fields=[
                ("S_NO", models.IntegerField(primary_key=True, serialize=False)),
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
                ("PatchedStatus", models.CharField(max_length=20)),
            ],
        ),
        migrations.DeleteModel(
            name="FileData",
        ),
    ]
