from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Remove every second factor (authenticator app and passkeys) of a user: lost phone/key recovery. The user enrols again at the next login.'

    def add_arguments(self, p):
        p.add_argument('username')

    def handle(self, *a, username, **o):
        try:
            user = get_user_model().objects.get(username=username)
        except get_user_model().DoesNotExist:
            raise CommandError(f'User {username} does not exist.')
        from django.core.cache import cache
        from rest_framework.authtoken.models import Token
        from zones.models import TotpDevice
        n = TotpDevice.objects.filter(user=user).delete()[0] + user.passkeys.all().delete()[0]
        Token.objects.filter(user=user).delete()
        cache.delete(f'mfa-fail:{user.pk}')
        self.stdout.write(f'{n} factors removed for {username}.')
