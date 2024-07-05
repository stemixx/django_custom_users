from django.contrib.auth import get_user_model, login
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import (
    LoginView,
    LogoutView,
    PasswordChangeView,
    PasswordResetView,
    PasswordResetConfirmView
)
from django.contrib.messages.views import SuccessMessageMixin
from django.contrib.sites.models import Site
from django.core.mail import send_mail
from django.db import transaction
from django.shortcuts import redirect, get_object_or_404
from django.views.generic import DetailView, CreateView, View, TemplateView, UpdateView
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from .models import CustomUser
from .forms import (
    CustomUserLoginForm,
    UserListForm,
    UserRegisterForm,
    UserPasswordChangeForm,
    UserUpdateForm,
    UserSetNewPasswordForm,
    UserForgotPasswordForm
)
from .services.mixins import UserIsNotAuthenticated

User = get_user_model()


class MainView(TemplateView):
    """
    Главная страница сайта
    """
    form_class = CustomUserLoginForm
    template_name = 'main.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Главная страница сайта'
        return context


class UserLoginView(LoginView):
    """
    Авторизация пользователя
    """
    form_class = CustomUserLoginForm
    template_name = 'user_login.html'
    success_url = reverse_lazy('main')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Авторизация'
        return context


class UserLogoutView(LogoutView):
    """
    Выход пользователя и переадресация на страницу авторизации
    """
    next_page = reverse_lazy('login')


class UsersListView(TemplateView):
    """
    Страница со списком пользователей
    """
    template_name = 'users_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        form = UserListForm()
        context['title'] = 'Список пользователей'
        context['form'] = form
        return context


class UserDetailView(DetailView):
    """
    Просмотр данных о пользователе
    """
    model = CustomUser
    context_object_name = 'user'
    template_name = 'user_detail.html'
    queryset = model.objects.all()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = f'Страница пользователя {self.object.email}'
        return context


class UserEditView(UpdateView):
    """
    Редактирование данных пользователя
    """
    model = CustomUser
    form_class = UserUpdateForm
    template_name = 'user_edit.html'

    def get_object(self, queryset=None):
        return get_object_or_404(CustomUser, id=self.request.user.id)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = f'Редактирование данных пользователя: {self.request.user.email}'
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
        return super(UserEditView, self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('user_detail', kwargs={'pk': self.object.id})


class UserPasswordChangeView(SuccessMessageMixin, PasswordChangeView):
    """
    Изменение пароля пользователя
    """
    form_class = UserPasswordChangeForm
    template_name = 'user_password_change.html'
    success_message = 'Ваш пароль был успешно изменён!'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Изменение пароля на сайте'
        return context

    def get_success_url(self):
        return reverse_lazy('user_detail', kwargs={'pk': self.request.user.id})


class UserForgotPasswordView(SuccessMessageMixin, PasswordResetView):
    """
    Сброс пароля по почте
    """
    form_class = UserForgotPasswordForm
    template_name = 'user_password_reset.html'
    success_url = reverse_lazy('main')
    success_message = 'Письмо с инструкцией по восстановлению пароля отправлена на ваш email'
    subject_template_name = 'password_subject_reset_mail.txt'
    email_template_name = 'password_reset_mail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Запрос на восстановление пароля'
        return context


class UserPasswordResetConfirmView(SuccessMessageMixin, PasswordResetConfirmView):
    """
    Установка нового пароля
    """
    form_class = UserSetNewPasswordForm
    template_name = 'user_password_set_new.html'
    success_url = reverse_lazy('main')
    success_message = 'Пароль успешно изменен. Можете авторизоваться на сайте.'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Установить новый пароль'
        return context


class UserRegisterView(UserIsNotAuthenticated, CreateView):
    """
    Регистрации на сайте
    """
    form_class = UserRegisterForm
    success_url = reverse_lazy('home')
    template_name = 'user_register.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Регистрация на сайте'
        return context

    def form_valid(self, form):
        user = form.save(commit=False)
        user.is_active = False
        user.save()
        # Функционал для генерации токена и отправки письма
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_url = reverse_lazy('confirm_email', kwargs={'uidb64': uid, 'token': token})
        current_site = Site.objects.get_current().domain
        send_mail(
            'Подтвердите свой электронный адрес',
            f'Пожалуйста, перейдите по следующей ссылке, чтобы подтвердить свой адрес электронной почты: '
            f'http://{current_site}{activation_url}',
            'stemix@mail.ru',
            [user.email],
            fail_silently=False,
        )

        return redirect('email_confirmation_sent')


class UserConfirmEmailView(View):
    """
    Подтверждение активации электронного адреса
    """

    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode('utf-8')
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
            return redirect('email_confirmed')
        else:
            return redirect('email_confirmation_failed')


class EmailConfirmationSentView(TemplateView):
    """
    Сообщение пользователю об успешной отправке письма активации
    """
    template_name = 'email_confirmation_sent.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Письмо активации отправлено'
        return context


class EmailConfirmedView(TemplateView):
    """
    Сообщение пользователю об успешной активации электронного адреса
    """
    template_name = 'email_confirmed.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Ваш электронный адрес активирован'
        return context


class EmailConfirmationFailedView(TemplateView):
    """
    Сообщение пользователю об ошибке при активации электронного адреса
    """
    template_name = 'email_confirmation_failed.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Ваш электронный адрес не активирован'
        return context
