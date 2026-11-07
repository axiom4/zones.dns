from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('zones', '0010_english_labels'),
    ]

    operations = [
        migrations.AlterField(
            model_name='passkey',
            name='credential_id',
            field=models.CharField(max_length=255, unique=True),
        ),
    ]
