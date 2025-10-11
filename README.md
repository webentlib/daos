# Installation

### 1. Create somewhere list of admin menu items like:
`stem/daos_menu.py`:
```python
from daos.menu import item


DAOS_MENU = [
    item('users.User', 'Users'),
    item('users.Group', 'Groups'),
]
```

Additional examples of `DAOS_MENU`:
```python
DAOS_MENU = [
    ...
    item('/admin/users/group/add/', 'Add Group'),
    item('/some-client-ui-url', 'Some Client UI url'),
    item('https://google.com', 'Google.com', target='_blank'),  # External
]
```

### 2. `settings.py`:

Add blank `'libraries': {},` to `TEMPLATES`

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            'libraries': {},  # added
        },
    },
]
```

Next settings pattern relies on `# Paths` section at the very top of your `# CUSTOM` block
```python
# Paths

STATICFILES_DIRS = []
FORMAT_MODULE_PATH = []
```

Else — adjust next settings somehow to `TEMPLATES`, `STATICFILES_DIRS` and `FORMAT_MODULE_PATH` directly:

```python
# Daos

DAOS_MENU = 'stem.daos_menu.DAOS_MENU'
STATICFILES_DIRS += [BASE_DIR / 'daos/static/']
FORMAT_MODULE_PATH += ['daos.formats']
USE_THOUSAND_SEPARATOR = True

TEMPLATES[0]['DIRS'] += [BASE_DIR / 'daos/templates']
TEMPLATES[0]['OPTIONS']['libraries']['daos_extras'] = 'daos.templatetags.daos_extras'
TEMPLATES[0]['OPTIONS']['context_processors'] += ['daos.menu.menu']

# from daos import patch_model_field_to_accept_group_param  # uncomment to enable `group` param
```

Block `# Paths` is optional depending on how your project's `TEMPLATES`, `STATICFILES_DIRS` and `FORMAT_MODULE_PATH` vars are organized.

Change path of `DAOS_MENU` and other settings to the path where your menu list and stuff actually placed.


# `urls.py`

Add explicit Daos and Django's admin static paths for `DEBUG = False` somewhere after `urlpatterns` declaration:

```
# DAOS STATIC

from django.urls import re_path
from daos.daos_serve import daos_serve

urlpatterns += [
    re_path(r'^static/(?P<path>.*)$', daos_serve),
]
```

# Common use cases

### 1. Now, all `ModelAdmins` inherited from `daos.admin.DaosModelAdmin` have 3 additional properties possible:
```python
from daos.admin import DaosModelAdmin
from apps.myapp.models import MyModel


@admin.register(MyModel)
class MyModelAdmin(DaosModelAdmin):
    list_select_related = []  # fields to `select_related` while in `list_editable`
    nowrap_fields = []        # columns to apply `white-space:nowrap` cc-rule
    additional_numeric_fields = []  # numeric columns added via `@staticmethod` must also be aligned to right
```

### 2. In addition, there is a convenient method to gather all `readonly_fields` with:
`readonly_fields = DaosModelAdmin.get_readonly(MyModel)`


# Additional use case (define `fieldsets` via `group` param)

Fieldsets can be defined like that:
```python
fieldsets = [
    [None, {
        'fields': DaosModelAdmin.get_group(MyModel, None)
    }],
    ['Counters', {
        'classes': ['collapse', 'open'],  # yes, 'open' now works properly with 'daos'
        'fields': DaosModelAdmin.get_group(MyModel, 'COUNTERS'),
    }],
]
```

To make `.get_group(...)` method work — uncomment that line in `settings.py`:  
`# from daos import patch_model_field_to_accept_group_param  # uncomment to enable `group` param`

It makes all subclasses of `django.db.models.fields.Field` accept `group` attribute:  
`count = models.IntegerField(group='COUNTERS')`


# Protect staff users from brute-force

The idea is to add a counter for failed attempts and drive it with custom admin auth form.

### 1. Inherit your 'User' from `daos.models.DaosUser`.  
   Do not forget to migrate:  
   $ python manage.py makemigrations  
   $ python manage.py migrate
    
### 2. Add `site.py` somewhere in `stem` folder with following content:
```python
from django.contrib import admin
from daos.forms import DaosAuthenticationForm


class CustomAdminSite(admin.AdminSite):
    index_title = 'MyAdmin'
    login_form = DaosAuthenticationForm

```
### 3. Add `apps.py` also somewhere in `stem` folder with following content:
```python
from django.contrib import admin
from django.contrib.admin import sites
from django.contrib.admin.apps import AdminConfig


class CustomAdminConfig(AdminConfig):
    name = 'stem'

    def ready(self):
        """https://stackoverflow.com/a/30056258/4117781"""
        from stem.site import CustomAdminSite

        base_admin_site = CustomAdminSite()
        admin.site = sites.site = base_admin_site
```
### 4. Add this to the very top of `INSTALLED_APPS` in `settings.py`:
```python
INSTALLED_APPS = [
    # Custom admin
    'stem.apps.CustomAdminConfig',
    
    ...
]
```

Done


# How to override things

Assumes, that 'daos' module will be installed in root dir.

1. To override python code — one can edit module itself, or create `daos` folder in `apps` and "inherit/extend".
2. To override templates — just specify another templates folder, to point it for example to root's templates `TEMPLATES[0]['DIRS'] += ['templates']` somewhere above `TEMPLATES[0]['DIRS'] += ['daos/templates']`. Then just create `admin` folder inside. 
3. To override static, similarly, one can specify something like `STATICFILES_DIRS = [BASE_DIR / 'static/']` above `STATICFILES_DIRS += [BASE_DIR / 'daos/static/']`.


# Key features

- Ускорены запросы, в случае если в списке есть возможность редактирования Foreign Key (проблема n+1);
- Защита от брутфорса сотрудников;
- Упрощены способы описания правил для генерации ui;
- Имеет и верхнее и боковое меню;
- Заголовки таблиц прилипают к экрану;
- Шапка и футер прилипают к экрану;
- Селекты имеют поиск, и множественный выбор (Select2);
- Все числа прижимаются к правому краю, числа разделяются пробелами каждые 3 знака и т.д. и т.п.;
- Минимизировано пустое бесполезное пространство (padding/margin и т.д.), перекомпанованы элементы поиска/добавления/действий в списке материалов; вырезаны хлебные крошки там где они не нужны;
- Короткие и информативные заголовки и <title>;
- Все эти изменения адаптируется и под моб. устройства;
- и т.д. и т.п.


# What's done in details

### Шапка:
- Плавающая
- Левое меню перенесено в Шапку, и доступно н всех страницах
- Пользовательские действия вынесены из Шапки на главную страницу

### Список:
- actions / search / add — объединены в одну строку и плавают
- Шапка таблицы, а также первые две th каждой строки — плавают
- Фильтр — плавает
- Пагинация — плавает
- Возможность указать поля, с запретом переноса строк (white-space: nowrap)
- Все числа выровнены по правому краю
- Числа разделяются пробелом каждые 3 знака
- Дроби разделяются точкой, а не запятой

### Детальная Страница:
- Нижняя Панель с кнопками плавает 
- Шапка inline-таблиц, а также первые две th каждой строки — плавают (как в списке)
- Чекбоксы — вытянуты
- Уменьшены расстояния между блоками
- Исправлен баг сворачивания/раскрытия объединённых полей

### Контролы (актуально для Списка и Детальной Страницы):
- Контролы приведены к единому размеру
- Виджет дата/время в одну строку
- Select 2 (в т.ч. multiple)

### Прочее:
- Упрощён <title> на всех страница
- Фавиконка
- Хлебные крошки вынесены в заголовки
- Главная страница вытянута на всю ширину окна
- Мобильная версия — юзабельна
- Убрана auto тема


# After any overrides check:

### This pages
| Name  | Link |
| --- | --- |
| Дашборд                             | http://127.0.0.1:8000/admin/                           |                                                                          
| Страница апликейшена                | http://127.0.0.1:8000/admin/users/                     |                                                    
| Список: С фильтром                  | http://127.0.0.1:8000/admin/users/user/                |                                                               
| Список: С редактируемыми полями     | http://127.0.0.1:8000/admin/users/group/               |                                               
| Список: Подтверждение удаления      | http://127.0.0.1:3000/admin/users/user/                |                                              
| Детальная: Страница добавления      | http://127.0.0.1:8000/admin/users/user/add/            |                                                  
| Детальная: С филдсетами             | http://127.0.0.1:3000/admin/users/user/1/change/       |                                                               
| Детальная: Простая                  | http://127.0.0.1:3000/admin/users/user/2/change/       |                                                        
| Детальная: История                  | http://127.0.0.1:3000/admin/users/user/1/history/      |                                                        
| Детальная: Подтверждение удаления   | http://127.0.0.1:3000/admin/users/user/1/delete/       |                                                       
| Пользователь: Вход для анонимного   | http://127.0.0.1:8000/admin/                           |                                   
| Пользователь: Сброс пароля          | http://127.0.0.1:3000/admin/users/user/1/password/     |                                                         
| Пользователь: Смена пароля          | http://127.0.0.1:3000/admin/password_change/           |                                                               
| Пользователь: Выход                 | http://127.0.0.1:3000/admin/logout/                    |                                          
| Документация: Главная               | http://127.0.0.1:8000/admin/doc/                       |                                       
| Документация: Список                | http://127.0.0.1:8000/admin/doc/models/                |                                              
| Документация: Детальная страница    | http://127.0.0.1:8000/admin/doc/models/admin.logentry/ |                                                             

### And this blocks
- Левая панель
- Хлебные крошки
- Вёрстка
- Мессаджи
- В светлой и тёмной темах
