from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, DateTimeField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import logging
import os
from dotenv import load_dotenv

# Загружаем переменные окружения из файла .env
load_dotenv()

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://site_db_wxv3_user:V203xlk86iX2DVGUbG5eKD53RnfLcVdR@dpg-cppg7hg8fa8c739fkf0g-a.oregon-postgres.render.com/site_db_wxv3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

membership = db.Table('membership',
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                      db.Column('department_id', db.Integer, db.ForeignKey('department.id'), primary_key=True)
                      )

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    manager = db.relationship('User', foreign_keys=[manager_id], backref='managed_departments')
    members = db.relationship('User', secondary=membership, backref='departments')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='assigned')
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    issued_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment = db.Column(db.Text, nullable=True)

    assigned_user = db.relationship('User', foreign_keys=[assigned_to], back_populates='tasks_assigned')
    issuer = db.relationship('User', foreign_keys=[issued_by], backref='issued_tasks')

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)

class Absence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    type = db.Column(db.String(20), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    bio = db.Column(db.String(255))
    passport_data = db.Column(db.String(255))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    department = db.relationship('Department', foreign_keys=[department_id], backref='users')
    position = db.Column(db.String(100))
    responsibilities = db.Column(db.Text)
    role = db.Column(db.String(20), nullable=False, default='Employee')
    tasks_assigned = db.relationship('Task', foreign_keys='Task.assigned_to', back_populates='assigned_user', lazy=True)
    absences = db.relationship('Absence', backref='user', lazy=True)
    ratings = db.relationship('Rating', backref='user', lazy=True)
    phone_number = db.Column(db.String(20))
    age = db.Column(db.String(20))
    gender = db.Column(db.String(20))
    status = db.Column(db.String(20))

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.Date, nullable=False)
    user = db.relationship('User', backref=db.backref('schedules', lazy=True))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class DepartmentForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Add Department')

class EditProfileForm(FlaskForm):
    bio = TextAreaField('Биография')
    passport_data = StringField('Паспортные данные')
    department = SelectField('Отдел', choices=[], coerce=int)
    position = StringField('Должность')
    responsibilities = TextAreaField('Должностные обязанности')
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Номер телефона')
    age = StringField('Возраст')
    gender = StringField('Пол')
    role = SelectField('Роль', choices=[('Admin', 'Администратор'), ('Manager', 'Менеджер'), ('Employee', 'Работник')], validators=[DataRequired()])
    submit = SubmitField('Сохранить изменения')

class TaskForm(FlaskForm):
    description = TextAreaField('Описание', validators=[DataRequired()])
    deadline = DateTimeField('Срок выполнения', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    assigned_to = SelectField('Назначить пользователю', coerce=int)
    submit = SubmitField('Создать задачу')

class LeaveForm(FlaskForm):
    date = StringField('Date', validators=[DataRequired()])
    reason = TextAreaField('Reason')
    submit = SubmitField('Submit Leave Request')

class RatingForm(FlaskForm):
    score = StringField('Score', validators=[DataRequired()])
    submit = SubmitField('Submit Rating')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def main():
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Имя пользователя уже занято. Пожалуйста, выберите другое имя.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Ваш аккаунт был создан! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Регистрация', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main'))
        else:
            flash('Неудачный вход. Пожалуйста, проверьте email и пароль', 'danger')
    return render_template('login.html', title='Вход', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('main'))

@app.route("/departments")
@login_required
def departments():
    all_departments = Department.query.all()
    return render_template('departments.html', departments=all_departments)

@app.route("/delete_user/<int:user_id>", methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin':
        flash('Вы не имеете прав для удаления пользователей.', 'danger')
        return redirect(url_for('main'))

    user = db.session.get(User, user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Пользователь успешно удален!', 'success')
    else:
        flash('Пользователь не найден.', 'danger')
    return redirect(url_for('main'))

@app.route("/admin_departments", methods=['GET', 'POST'])
@login_required
def admin_departments():
    if current_user.role != 'Admin':
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('main'))

    form = DepartmentForm()
    task_form = TaskForm()
    leave_form = LeaveForm()
    rating_form = RatingForm()

    if form.validate_on_submit():
        department = Department(name=form.name.data, description=form.description.data)
        db.session.add(department)
        db.session.commit()
        flash('Отдел успешно добавлен!', 'success')
        return redirect(url_for('admin_departments'))

    if task_form.validate_on_submit():
        assigned_to_user = User.query.filter_by(username=task_form.assigned_to.data).first()
        if assigned_to_user:
            deadline = datetime.strptime(task_form.deadline.data, '%Y-%m-%dT%H:%M')
            task = Task(description=task_form.description.data, deadline=deadline, assigned_to=assigned_to_user.id)
            db.session.add(task)
            db.session.commit()
            flash('Задание успешно создано!', 'success')
        else:
            flash('Пользователь не найден!', 'danger')

    departments = Department.query.all()
    all_users = User.query.all()
    return render_template('admin_departments.html', title='Администрирование отделов', form=form,
                           departments=departments, task_form=task_form, leave_form=leave_form,
                           rating_form=rating_form, all_users=all_users)

@app.route("/join_department/<int:department_id>", methods=['GET', 'POST'])
@login_required
def join_department(department_id):
    department = db.session.get(Department, department_id)
    if current_user not in department.members:
        department.members.append(current_user)
        db.session.commit()
        flash('Вы присоединились к отделу!', 'success')
    else:
        flash('Вы уже состоите в этом отделе.', 'info')
    return redirect(url_for('departments'))

@app.route("/delete_department/<int:department_id>", methods=['POST'])
@login_required
def delete_department(department_id):
    department = db.session.get(Department, department_id)
    db.session.delete(department)
    db.session.commit()
    flash('Отдел успешно удален!', 'success')
    return redirect(url_for('admin_departments'))

@app.route("/profile/<int:user_id>", methods=['GET', 'POST'])
@login_required
def profile(user_id):
    user = db.session.get(User, user_id)
    form = EditProfileForm()
    task_form = TaskForm()

    if form.validate_on_submit():
        user.bio = form.bio.data
        user.passport_data = form.passport_data.data
        user.department_id = form.department.data
        user.position = form.position.data
        user.responsibilities = form.responsibilities.data
        db.session.commit()
        flash('Ваш профиль был обновлен!', 'success')
        return redirect(url_for('profile', user_id=user_id))

    form.bio.data = user.bio
    form.passport_data.data = user.passport_data
    form.department.data = user.department_id
    form.position.data = user.position
    form.responsibilities.data = user.responsibilities

    user_tasks = user.tasks_assigned
    department = db.session.get(Department, user.department_id)

    department_name = department.name if department else "Нет отдела"

    return render_template('profile.html', title='Профиль', form=form, user=user, user_tasks=user_tasks,
                           task_form=task_form, department_name=department_name)

@app.route("/edit_profile/<int:user_id>", methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    form = EditProfileForm()
    user = db.session.get(User, user_id)

    if user.id != current_user.id and current_user.role != 'Admin':
        flash('Вы не имеете прав на редактирование этого профиля.', 'danger')
        return redirect(url_for('main'))

    departments = Department.query.all()
    department_choices = [(department.id, department.name) for department in departments]
    form.department.choices = department_choices

    if form.validate_on_submit():
        user.bio = form.bio.data
        user.passport_data = form.passport_data.data
        user.department_id = form.department.data
        user.position = form.position.data
        user.responsibilities = form.responsibilities.data
        user.email = form.email.data
        user.phone_number = form.phone_number.data
        user.age = form.age.data
        user.gender = form.gender.data
        user.role = form.role.data
        db.session.commit()
        flash('Ваш профиль был обновлен!', 'success')
        return redirect(url_for('profile', user_id=user_id))

    form.bio.data = user.bio
    form.passport_data.data = user.passport_data
    form.department.data = user.department_id
    form.position.data = user.position
    form.responsibilities.data = user.responsibilities
    form.email.data = user.email
    form.phone_number.data = user.phone_number
    form.age.data = user.age
    form.gender.data = user.gender
    form.role.data = user.role

    return render_template('edit_profile.html', title='Редактировать профиль', form=form, user=user)

@app.route("/edit_department/<int:department_id>", methods=['GET', 'POST'])
@login_required
def edit_department(department_id):
    department = Department.query.get_or_404(department_id)
    if current_user.role not in ['Admin', 'Manager'] or (
            current_user.role == 'Manager' and department.manager_id != current_user.id):
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('main'))

    form = DepartmentForm(obj=department)
    all_users = User.query.all()

    if form.validate_on_submit():
        department.name = form.name.data
        department.description = form.description.data
        manager_id = request.form.get('manager')
        department.manager_id = manager_id

        manager = User.query.get(manager_id)
        if manager:
            manager.role = 'Manager'

        db.session.commit()
        flash('Изменения сохранены!', 'success')
        return redirect(url_for('admin_departments'))

    return render_template('edit_department.html', form=form, department=department, all_users=all_users)

@app.route("/assign_user_to_department/<int:department_id>", methods=['POST'])
@login_required
def assign_user_to_department(department_id):
    department = Department.query.get_or_404(department_id)
    if current_user.role not in ['Admin', 'Manager'] or (
            current_user.role == 'Manager' and department.manager_id != current_user.id):
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('main'))

    user_id = request.form.get('user')
    user = User.query.get_or_404(user_id)
    if user not in department.members:
        department.members.append(user)
        db.session.commit()
        flash('Пользователь успешно добавлен в отдел!', 'success')
    else:
        flash('Пользователь уже в этом отделе.', 'info')
    return redirect(url_for('admin_departments'))

@app.route('/manager_page')
@login_required
def manager_page():
    if current_user.role != 'Manager':
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('main'))
    return render_template('admin_departments.html')

@app.route("/assign_task", methods=['POST'])
@login_required
def assign_task():
    if current_user.role not in ['Admin', 'Manager']:
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('main'))

    description = request.form['description']
    deadline = request.form['deadline']
    assigned_to = request.form['assigned_to']
    issued_by = request.form['issued_by']

    app.logger.debug(f"description: {description}, deadline: {deadline}, assigned_to: {assigned_to}, issued_by: {issued_by}")

    if not assigned_to:
        flash('Значение "assigned_to" не передано.', 'danger')
        return redirect(url_for('tasks'))

    try:
        deadline = datetime.strptime(deadline, '%Y-%m-%dT%H:%M')
    except ValueError:
        flash('Неправильный формат даты и времени.', 'danger')
        return redirect(url_for('tasks'))

    task = Task(description=description, deadline=deadline, assigned_to=assigned_to, issued_by=issued_by, status='assigned')
    db.session.add(task)
    db.session.commit()
    flash('Задача успешно назначена!', 'success')
    return redirect(url_for('tasks'))

@app.route("/tasks")
@login_required
def tasks():
    status = request.args.get('status')
    if status:
        tasks = Task.query.filter_by(status=status).all()
    else:
        tasks = Task.query.all()
    return render_template('tasks.html', tasks=tasks, status=status)

@app.route("/submit_for_review/<int:task_id>", methods=['POST'])
@login_required
def submit_for_review(task_id):
    task = db.session.get(Task, task_id)
    if not task or task.assigned_to != current_user.id:
        flash('Задача не найдена или у вас нет прав для выполнения этой операции.', 'danger')
        return redirect(url_for('tasks'))

    task.status = 'in_review'
    db.session.commit()
    flash('Задача отправлена на проверку!', 'success')
    return redirect(url_for('tasks'))

@app.route("/review_task/<int:task_id>", methods=['GET', 'POST'])
@login_required
def review_task(task_id):
    task = db.session.get(Task, task_id)
    if not task:
        flash('Задача не найдена.', 'danger')
        return redirect(url_for('tasks'))
    if current_user.role not in ['Admin', 'Manager']:
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('tasks'))

    if request.method == 'POST':
        action = request.form.get('action')
        comment = request.form.get('comment', '')

        if action == 'approve':
            task.status = 'completed'
            flash('Задача завершена!', 'success')
        elif action == 'reject':
            task.status = 'assigned'
            task.comment = comment  # Сохраним комментарий для доработки
            flash('Задача отправлена на доработку!', 'warning')
        else:
            flash('Неизвестное действие.', 'danger')
        db.session.commit()
        return redirect(url_for('tasks', status='in_review'))

    return render_template('review_task.html', task=task)

@app.route("/sick_leave/<int:user_id>", methods=['POST'])
@login_required
def sick_leave(user_id):
    user = db.session.get(User, user_id)
    if user:
        # Логика для обработки больничного (например, создание записи о больничном в БД)
        flash('Больничный успешно обработан!', 'success')
        return redirect(url_for('profile', user_id=user_id))
    else:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('profile', user_id=current_user.id))

@app.route("/mark_absence/<int:user_id>", methods=['POST'])
@login_required
def mark_absence(user_id):
    if current_user.role not in ['Admin', 'Manager']:
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('main'))

    user = db.session.get(User, user_id)
    if user:
        start_date = request.form['start_date']
        end_date = request.form['end_date'] or start_date  # Если дата окончания не указана, берем дату начала
        type_absence = request.form['type']

        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d')

        absence = Absence(user_id=user.id, start_date=start_date, end_date=end_date, type=type_absence)
        db.session.add(absence)
        db.session.commit()
        flash('Отсутствие успешно отмечено!', 'success')
    else:
        flash('Пользователь не найден.', 'danger')

    return redirect(url_for('profile', user_id=user_id))

@app.route("/users")
@login_required
def users():
    if current_user.role not in ['Admin', 'Manager']:
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('main'))

    all_users = User.query.all()
    return render_template('users.html', title='Все пользователи', users=all_users)

@app.route('/weekly_schedule')
@login_required
def weekly_schedule():
    if current_user.role != 'Employee':
        return "Доступ запрещен", 403

    today = datetime.today()
    start_week = today - timedelta(days=today.weekday())
    days_of_week = [start_week + timedelta(days=i) for i in range(7)]

    schedules = []
    for day in days_of_week:
        schedule = Schedule.query.filter_by(user_id=current_user.id, day=day).first()
        if not schedule:
            schedule = Schedule(user_id=current_user.id, day=day)
            db.session.add(schedule)
            db.session.commit()
        schedules.append(schedule)

    tasks = Task.query.filter_by(assigned_to=current_user.id).all()
    return render_template('weekly_schedule.html', schedules=schedules, tasks=tasks)

def auto_upgrade():
    """Automatically upgrade the database"""
    with app.app_context():
        upgrade()

if __name__ == '__main__':
    auto_upgrade()  # Выполните миграции перед запуском приложения
    app.run(debug=True , host='0.0.0.0')