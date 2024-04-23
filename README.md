# django_rest_with_user_roles_permission
django_rest_with_user_roles_permission Django Rest framework with user roles and permissions

- Base Authentication Django APP with JWT Authentication

- ## Setup

- The first thing to do is to clone the repository:

- git clone - https://github.com/cis-muzahid/django_rest_with_user_roles_permission


- Create a virtual environment to install dependencies in and activate it:


- python3.12 -m venv env_name


- source env_name/bin/activate


- Then install the dependencies:


- (env_name)$ pip install -r requirements.txt


- Note the `(env_name)` in front of the prompt. This indicates that this terminal
- session operates in a virtual environment set up by `virtualenv`.

- Once `pip` has finished downloading the dependencies:

- Migrate the database

- (env_name)$ python manage.py migrate

- Go to the root DIR:

- (env_name)$ python manage.py runserver

- And navigate to `http://127.0.0.1:8000/`.
