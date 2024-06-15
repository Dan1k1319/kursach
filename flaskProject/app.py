from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_bcrypt import Bcrypt
from datetime import datetime
from wtforms.fields import DateTimeField, SelectField

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Модель для отделов
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    members = db.relationship('User', secondary='membership', backref='departments')

    membership = db.Table('membership',
                          db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                          db.Column('department_id', db.Integer, db.ForeignKey('department.id'), primary_key=True))

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_user = db.relationship('User', backref='assigned_tasks', overlaps="tasks_assigned,assigned_user")

class Leave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(255))

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    bio = db.Column(db.String(255))
    passport_data = db.Column(db.String(255))
    department = db.Column(db.String(100))
    position = db.Column(db.String(100))
    responsibilities = db.Column(db.Text)
    tasks_assigned = db.relationship('Task', backref='assignee', lazy=True, overlaps="assigned_tasks,assigned_user")
    leaves = db.relationship('Leave', backref='user', lazy=True)
    ratings = db.relationship('Rating', backref='user', lazy=True)

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
    bio = TextAreaField('Bio')
    passport_data = StringField('Passport Data')
    department = SelectField('Department', choices=[], coerce=int)
    position = StringField('Position')
    responsibilities = TextAreaField('Responsibilities')
    submit = SubmitField('Save Changes')

class TaskForm(FlaskForm):
    description = TextAreaField('Description', validators=[DataRequired()])
    deadline = DateTimeField('Deadline', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    assigned_to = StringField('Assigned To', validators=[DataRequired()])
    submit = SubmitField('Create Task')

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
            flash('Username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

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
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

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
    user = db.session.get(User, user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User has been deleted successfully!', 'success')
    return redirect(url_for('admin_department_members', department_id=current_user.departments[0].id))

@app.route("/admin_departments", methods=['GET', 'POST'])
@login_required
def admin_departments():
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
            deadline = datetime.strptime(task_form.deadline.data, '%Y-%m-%dT%H:%M')  # Исправлено для правильного формата
            task = Task(description=task_form.description.data, deadline=deadline, assigned_to=assigned_to_user.id)
            db.session.add(task)
            db.session.commit()
            flash('Задание успешно создано!', 'success')
        else:
            flash('Пользователь не найден!', 'danger')

    departments = Department.query.all()
    return render_template('admin_departments.html', title='Администрирование отделов', form=form,
                           departments=departments, task_form=task_form, leave_form=leave_form,
                           rating_form=rating_form)

@app.route("/admin_department_members/<int:department_id>", methods=['GET', 'POST'])
@login_required
def admin_department_members(department_id):
    department = db.session.get(Department, department_id)
    task_form = TaskForm()
    leave_form = LeaveForm()
    rating_form = RatingForm()

    if task_form.validate_on_submit() and 'description' in request.form and 'deadline' in request.form and 'assigned_to' in request.form:
        assigned_to_user_id = int(request.form['assigned_to'])
        assigned_to_user = User.query.get(assigned_to_user_id)
        if assigned_to_user:
            deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%dT%H:%M')  # Исправлено для правильного формата
            task = Task(description=request.form['description'], deadline=deadline, assigned_to=assigned_to_user_id)
            db.session.add(task)
            db.session.commit()
            flash('Task successfully assigned!', 'success')
        else:
            flash('User not found!', 'danger')

    if request.method == 'POST' and 'user_id' in request.form:
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        if user in department.members:
            department.members.remove(user)
            db.session.commit()
            flash('User successfully removed from the department!', 'success')
        else:
            flash('User is not a member of this department!', 'danger')
        return redirect(url_for('admin_department_members', department_id=department.id))

    all_users = User.query.all()  # Fetch all registered users

    return render_template('admin_department_members.html', title='Manage Department Members', department=department,
                           task_form=task_form, leave_form=leave_form, rating_form=rating_form, all_users=all_users)

@app.route("/join_department/<int:department_id>", methods=['GET', 'POST'])
@login_required
def join_department(department_id):
    department = db.session.get(Department, department_id)
    if current_user not in department.members:
        department.members.append(current_user)
        db.session.commit()
        flash('You have joined the department!', 'success')
    else:
        flash('You are already a member of this department.', 'info')
    return redirect(url_for('departments'))

@app.route("/delete_department/<int:department_id>", methods=['POST'])
@login_required
def delete_department(department_id):
    department = db.session.get(Department, department_id)
    db.session.delete(department)
    db.session.commit()
    flash('Department has been deleted successfully!', 'success')
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
        user.department = form.department.data
        user.position = form.position.data
        user.responsibilities = form.responsibilities.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile', user_id=user_id))

    form.bio.data = user.bio
    form.passport_data.data = user.passport_data
    form.department.data = user.department
    form.position.data = user.position
    form.responsibilities.data = user.responsibilities

    user_tasks = user.tasks_assigned
    department = db.session.get(Department, user.department)

    department_name = department.name if department else "No Department"

    return render_template('profile.html', title='Profile', form=form, user=user, user_tasks=user_tasks, task_form=task_form, department_name=department_name)

@app.route("/edit_profile/<int:user_id>", methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    form = EditProfileForm()
    user = db.session.get(User, user_id)

    if user.id != current_user.id:
        flash('You are not authorized to edit this profile.', 'danger')
        return redirect(url_for('main'))

    departments = Department.query.all()
    department_choices = [(department.id, department.name) for department in departments]
    form.department.choices = department_choices

    if form.validate_on_submit():
        user.bio = form.bio.data
        user.passport_data = form.passport_data.data
        user.department = form.department.data
        user.position = form.position.data
        user.responsibilities = form.responsibilities.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile', user_id=user_id))

    form.bio.data = user.bio
    form.passport_data.data = user.passport_data
    form.department.data = user.department
    form.position.data = user.position
    form.responsibilities.data = user.responsibilities

    return render_template('edit_profile.html', title='Edit Profile', form=form, user=user)

if __name__ == '__main__':
    app.run(debug=True)