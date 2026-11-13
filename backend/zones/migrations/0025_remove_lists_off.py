from django.db import migrations


def remove_lists_off(apps, schema_editor):
    Setting = apps.get_model('zones', 'Setting')
    Setting.objects.filter(key='lists_off').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('zones', '0024_dhcp6_lease'),
    ]

    operations = [
        migrations.RunPython(remove_lists_off, migrations.RunPython.noop),
    ]
