# Generated by Django 3.0 on 2020-03-10 18:14

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Url',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url_value', models.CharField(max_length=455)),
                ('url_prob', models.CharField(max_length=20)),
            ],
        ),
    ]
