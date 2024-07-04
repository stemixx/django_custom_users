from django import forms
from django.contrib.auth import get_user_model
from .models import CustomUser
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm


class CustomUserLoginForm(AuthenticationForm):
    username = forms.EmailField(max_length=254, widget=forms.TextInput(attrs={'placeholder': 'e-mail'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'password'}))


class UserListForm(forms.Form):
    """
    Форма отображения списка пользователей
    """

    def __init__(self, *args, **kwargs):
        super(UserListForm, self).__init__(*args, **kwargs)
        users = CustomUser.objects.all()
        choices = [(user.id, user.email) for user in users]
        self.fields['users'] = forms.ChoiceField(choices=choices, widget=forms.Select, label="Пользователи")


class UserUpdateForm(UserChangeForm):
    """
    Форма обновления данных пользователя
    """
    email = forms.EmailField(disabled=True)

    class Meta:
        model = CustomUser
        fields = ('email', 'username')

    def __init__(self, *args, **kwargs):
        """
        Обновление стилей формы под bootstrap
        """
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({
                'class': 'form-control',
                'autocomplete': 'off'
            })



class ProfileUpdateForm(UserChangeForm):
    """
    Форма обновления данных профиля пользователя
    """
    class Meta:
        model = CustomUser
        fields = ('username',)

    def __init__(self, *args, **kwargs):
        """
        Обновление стилей формы обновления
        """
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({
                'class': 'form-control',
                'autocomplete': 'off'
            })


class UserRegisterForm(UserCreationForm):
    """
    Переопределенная форма регистрации пользователей
    """

    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = UserCreationForm.Meta.fields + ('email', )

    def clean_email(self):
        """
        Проверка email на уникальность
        """
        email = self.cleaned_data.get('email')
        # username = self.cleaned_data.get('username')
        # if email and User.objects.filter(email=email).exclude(username=username).exists():
        if email and CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError('Такой email уже используется в системе!')
        return email

    def __init__(self, *args, **kwargs):
        """
        Обновление стилей формы регистрации
        """
        super().__init__(*args, **kwargs)
        for field in self.fields:
            print(self.fields)
            # self.fields['pk'].widget.attrs.update({"placeholder": 'Придумайте свой id'})
            self.fields['email'].widget.attrs.update({"placeholder": 'Введите свой email'})

            self.fields['password1'].widget.attrs.update({"placeholder": 'Придумайте свой пароль'})
            self.fields['password2'].widget.attrs.update({"placeholder": 'Повторите придуманный пароль'})
            self.fields[field].widget.attrs.update({"class": "form-control", "autocomplete": "off"})


class UserLoginForm(AuthenticationForm):
    """
    Форма авторизации на сайте
    """

    def __init__(self, *args, **kwargs):
        """
        Обновление стилей формы регистрации
        """
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields['email'].widget.attrs['placeholder'] = 'Логин пользователя'
            self.fields['password'].widget.attrs['placeholder'] = 'Пароль пользователя'
            self.fields['email'].label = 'Логин'
            self.fields[field].widget.attrs.update({
                'class': 'form-control',
                'autocomplete': 'off'
            })


class CustomUserCreationForm(UserCreationForm):

    class Meta(UserCreationForm):
        model = CustomUser
        fields = ('email',)


class CustomUserChangeForm(UserChangeForm):

    class Meta:
        model = CustomUser
        fields = ('email',)
