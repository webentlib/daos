from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.utils import timezone
from apps.users.models import User


class DaosAuthenticationForm(AuthenticationForm):
    """
    Каждый раз, когда происходит неудачного попытка входа в систему —
    Django вызывает метод `get_invalid_login_error`.
    Перехватываем этот метод, и записываем неудачные попытки входа соответствующему username.

    Каждый раз, когда происходит удачная попытка входа в систему —
    Django вызывает метод `confirm_login_allowed`, проверяющий на `is_active`.
    Перехватываем этот метод, и проверяем также на `failed_login_attempts`.

    ПОДКЛЮЧЕНИЕ

    1. models.py:User

    failed_login_attempts = models.IntegerField(default=0)
    last_failed_login_attempt_at = models.DateTimeField(null=True, blank=True)

    2. urls.py

    from django.contrib.auth.views import LoginView
    from apps.users.forms import DaosAuthenticationForm


    urlpatterns = [
        path('admin/login/', LoginView.as_view(authentication_form=DaosAuthenticationForm, template_name='admin/login.html'), name='login'),
        ...
    ]
    """

    def get_invalid_login_error(self):
        username = self.cleaned_data.get('username')
        user = User.objects.filter(username=username).first()
        if user:
            user.failed_login_attempts += 1
            user.last_failed_login_attempt_at = timezone.now()
            user.save()
        return super().get_invalid_login_error()

    def confirm_login_allowed(self, user):
        self._check_failed_login_attempts(user)
        return super().confirm_login_allowed(user)

    @staticmethod
    def _check_failed_login_attempts(user):
        if user and user.failed_login_attempts > 5:
            raise ValidationError('Too many failed login attempts')