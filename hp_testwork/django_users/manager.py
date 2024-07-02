# from django.contrib.auth.base_user import BaseUserManager
# from django.utils.translation import gettext_lazy as glazy
#
# """
#     Custom user model manager where email is the unique identifiers
#     for authentication instead of usernames.
#     """
#
#
# class CustomUserManager(BaseUserManager):
#     """
#     Custom user model manager where email is the unique identifiers
#     for authentication instead of usernames.
#     """
#
#     def create_user(self, email, password, **extra_fields):
#         """
#         Create and save a User with the given email and password.
#         """
#         if not email:
#             raise ValueError(glazy('The Email must be set'))
#         email = self.normalize_email(email)
#
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save()
#         return user
#
#     def create_superuser(self, email, password, **extra_fields):
#         """
#         Create and save a SuperUser with the given email and password.
#         """
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#         extra_fields.setdefault('is_active', True)
#
#         if extra_fields.get('is_staff') is not True:
#             raise ValueError(glazy('Superuser must have is_staff=True.'))
#         if extra_fields.get('is_superuser') is not True:
#             raise ValueError(glazy('Superuser must have is_superuser=True.'))
#         return self.create_user(email, password, **extra_fields)
#
#     def get_full_name(self):
#         '''
#         Returns the first_name plus the last_name, with a space in between.
#         '''
#         full_name = f'{self.first_name} {self.last_name}'
#         return full_name.strip()
#
#     def get_short_name(self):
#         '''
#         Returns the short name for the user.
#         '''
#         return self.first_name
