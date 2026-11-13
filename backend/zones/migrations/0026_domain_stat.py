from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('zones', '0025_remove_lists_off'),
    ]

    operations = [
        migrations.CreateModel(
            name='DomainStat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hour', models.DateTimeField()),
                ('domain', models.CharField(blank=True, max_length=253)),
                ('n', models.PositiveBigIntegerField(default=0)),
                ('local', models.PositiveBigIntegerField(default=0)),
                ('forwarded', models.PositiveBigIntegerField(default=0)),
                ('blocked', models.PositiveBigIntegerField(default=0)),
                ('error', models.PositiveBigIntegerField(default=0)),
                ('ms', models.PositiveBigIntegerField(default=0)),
            ],
            options={
                'indexes': [models.Index(fields=['domain', 'hour'], name='idx_domain_stat_dom_hr')],
                'constraints': [models.UniqueConstraint(fields=('hour', 'domain'), name='unique_domain_stat')],
            },
        ),
    ]
