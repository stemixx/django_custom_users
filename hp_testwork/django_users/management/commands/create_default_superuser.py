import os
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Creates an admin user non-interactively if it doesn't exist"

    def add_arguments(self, parser):
        parser.add_argument('--username', help="Admin's username")
        parser.add_argument('--email', help="Admin's email")
        parser.add_argument('--password', help="Admin's password")
        parser.add_argument('--no-input', help="Read options from the environment",
                            action='store_true')

    def handle(self, *args, **options):
        User = get_user_model()

        if options['no_input']:
            options['email'] = os.environ['DJANGO_SUPERUSER_EMAIL']
            options['username'] = os.environ['DJANGO_SUPERUSER_USERNAME']
            options['password'] = os.environ['DJANGO_SUPERUSER_PASSWORD']

        if User.objects.filter(username=options['username']).exists():
            self.stdout.write(self.style.SUCCESS(f"Admin user '{options['username']}' already exists"))
        elif User.objects.filter(email=options['email']).exists():
            self.stdout.write(self.style.SUCCESS(f"Admin with email '{options['email']}' already exists"))
        else:
            User.objects.create_superuser(username=options['username'],
                                          email=options['email'],
                                          password=options['password'])
