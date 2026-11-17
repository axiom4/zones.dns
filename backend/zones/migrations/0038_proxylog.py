from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('zones', '0037_setting_value_text'),
    ]

    operations = [
        migrations.CreateModel(
            name='ProxyLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('time', models.DateTimeField(db_index=True, default=django.utils.timezone.now, editable=False)),
                ('client', models.CharField(max_length=45)),
                ('method', models.CharField(max_length=12)),
                ('host', models.CharField(db_index=True, max_length=253)),
                ('url', models.CharField(blank=True, default='', max_length=500)),
                ('outcome', models.CharField(choices=[('allowed', 'allowed'), ('filtered', 'filtered'), ('blocked', 'blocked'), ('error', 'error')], max_length=12)),
                ('status', models.PositiveSmallIntegerField(default=200)),
                ('reason', models.CharField(blank=True, default='', max_length=255)),
                ('ms', models.PositiveIntegerField(default=0)),
            ],
            options={
                'indexes': [
                    models.Index(fields=['host', 'time'], name='plog_host_time'),
                    models.Index(fields=['outcome', 'time'], name='plog_outcome_time'),
                    models.Index(fields=['client', 'time'], name='plog_client_time'),
                ],
            },
        ),
    ]
