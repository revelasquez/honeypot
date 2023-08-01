# Generated by Django 4.0.4 on 2022-05-16 12:38

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('admin_honeypot', '0005_alter_hashcashmetadata_bits_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Preferences',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('has_fail2ban_log', models.BooleanField(verbose_name='fail2ban log')),
                ('bits_to_increase', models.IntegerField(verbose_name='bits to increase')),
                ('salt_length', models.IntegerField(verbose_name='salt length')),
                ('hashcash_validity_in_minutes', models.IntegerField(verbose_name='hashcash validity in minutes')),
            ],
            options={
                'verbose_name_plural': 'preferences',
            },
        ),
        migrations.AlterField(
            model_name='loginattempt',
            name='hashcash_stamp',
            field=models.CharField(max_length=255, verbose_name='hashcash stamp', null=True),
        ),
    ]