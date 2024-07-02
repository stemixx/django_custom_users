from django.contrib.auth import get_user_model, login
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView, PasswordChangeView, PasswordResetView, PasswordResetConfirmView
from django.contrib.messages.views import SuccessMessageMixin
# from django.contrib.sites.models import Site
from django.core.mail import send_mail
from django.db import transaction
from django.shortcuts import redirect, get_object_or_404
from django.views.generic import DetailView, CreateView, View, TemplateView, UpdateView
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from .models import CustomUser
from .forms import CustomUserLoginForm, UserRegisterForm, UserUpdateForm, ProfileUpdateForm
from .services.mixins import UserIsNotAuthenticated

User = get_user_model()


class CustomUserLoginView(LoginView):
    """
    Представление для авторизации пользователей
    """
    form_class = CustomUserLoginForm
    # authentication_form = CustomUserLoginForm
    template_name = 'django_users/user_login.html'


class ProfileDetailView(DetailView):
    """
    Представление для просмотра профиля
    """
    model = CustomUser
    context_object_name = 'profile'
    template_name = 'django_users/profile_detail.html'
    queryset = model.objects.all()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = f'Страница пользователя {self.object.email}'
        return context


class ProfileUpdateView(UpdateView):
    """
    Представление для редактирования профиля
    """
    model = CustomUser
    form_class = ProfileUpdateForm
    template_name = 'django_users/profile_edit.html'

    def get_object(self, queryset=None):
        # return self.request.user.id
        return get_object_or_404(CustomUser, id=self.request.user.id)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = f'Редактирование профиля пользователя: {self.request.user.email}'
        if self.request.POST:
            context['user_form'] = UserUpdateForm(self.request.POST, instance=self.request.user)
        else:
            context['user_form'] = UserUpdateForm(instance=self.request.user)
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        user_form = context['user_form']
        with transaction.atomic():
            if all([form.is_valid(), user_form.is_valid()]):
                user_form.save()
                form.save()
            else:
                context.update({'user_form': user_form})
                return self.render_to_response(context)
        return super(ProfileUpdateView, self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('profile_detail', kwargs={'id': self.object.uuid})


class UserLoginView(SuccessMessageMixin, LoginView):
    """
    Авторизация на сайте
    """
    form_class = CustomUserLoginForm
    template_name = 'django_users/user_login.html'
    next_page = 'home'
    success_message = 'Добро пожаловать на сайт!'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Авторизация на сайте'
        return context


# class UserPasswordChangeView(SuccessMessageMixin, PasswordChangeView):
#     """
#     Изменение пароля пользователя
#     """
#     form_class = UserPasswordChangeForm
#     template_name = 'django_users/user_password_change.html'
#     success_message = 'Ваш пароль был успешно изменён!'
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['title'] = 'Изменение пароля на сайте'
#         return context
#
#     def get_success_url(self):
#         return reverse_lazy('profile_detail', kwargs={'slug': self.request.user.profile.slug})


# class UserForgotPasswordView(SuccessMessageMixin, PasswordResetView):
#     """
#     Представление по сбросу пароля по почте
#     """
#     form_class = UserForgotPasswordForm
#     template_name = 'system/registration/user_password_reset.html'
#     success_url = reverse_lazy('home')
#     success_message = 'Письмо с инструкцией по восстановлению пароля отправлена на ваш email'
#     subject_template_name = 'system/email/password_subject_reset_mail.txt'
#     email_template_name = 'system/email/password_reset_mail.html'
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['title'] = 'Запрос на восстановление пароля'
#         return context
#
#
# class UserPasswordResetConfirmView(SuccessMessageMixin, PasswordResetConfirmView):
#     """
#     Представление установки нового пароля
#     """
#     form_class = UserSetNewPasswordForm
#     template_name = 'system/registration/user_password_set_new.html'
#     success_url = reverse_lazy('home')
#     success_message = 'Пароль успешно изменен. Можете авторизоваться на сайте.'
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['title'] = 'Установить новый пароль'
#         return context
#
#
# class UserRegisterView(UserIsNotAuthenticated, CreateView):
#     """
#     Представление регистрации на сайте с формой регистрации
#     """
#     form_class = UserRegisterForm
#     success_url = reverse_lazy('home')
#     template_name = 'system/registration/user_register.html'
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['title'] = 'Регистрация на сайте'
#         return context
#
#     def form_valid(self, form):
#         user = form.save(commit=False)
#         user.is_active = False
#         user.save()
#         # Функционал для отправки письма и генерации токена
#         token = default_token_generator.make_token(user)
#         uid = urlsafe_base64_encode(force_bytes(user.pk))
#         activation_url = reverse_lazy('confirm_email', kwargs={'uidb64': uid, 'token': token})
#         current_site = Site.objects.get_current().domain
#         send_mail(
#             'Подтвердите свой электронный адрес',
#             f'Пожалуйста, перейдите по следующей ссылке, чтобы подтвердить свой адрес электронной почты: http://{current_site}{activation_url}',
#             'service.notehunter@gmail.com',
#             [user.email],
#             fail_silently=False,
#         )
#         return redirect('email_confirmation_sent')
#
#
# class UserConfirmEmailView(View):
#     def get(self, request, uidb64, token):
#         try:
#             uid = urlsafe_base64_decode(uidb64)
#             user = User.objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             user = None
#
#         if user is not None and default_token_generator.check_token(user, token):
#             user.is_active = True
#             user.save()
#             login(request, user)
#             return redirect('email_confirmed')
#         else:
#             return redirect('email_confirmation_failed')
#
#
# class EmailConfirmationSentView(TemplateView):
#     template_name = 'system/registration/email_confirmation_sent.html'
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['title'] = 'Письмо активации отправлено'
#         return context
#
#
# class EmailConfirmedView(TemplateView):
#     template_name = 'system/registration/email_confirmed.html'
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['title'] = 'Ваш электронный адрес активирован'
#         return context
#
#
# class EmailConfirmationFailedView(TemplateView):
#     template_name = 'system/registration/email_confirmation_failed.html'
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['title'] = 'Ваш электронный адрес не активирован'
#         return context



# class LoginUser(DataMixin, LoginView):
#     form_class = AuthenticationForm
#     template_name = 'women/user_login.html'
#
#     def get_context_data(self, *, object_list=None, **kwargs):
#         context = super().get_context_data(**kwargs)
#         c_def = self.get_user_context(title="Авторизация")
#         return dict(list(context.items()) + list(c_def.items()))