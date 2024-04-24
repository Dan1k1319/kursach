from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_bcrypt import Bcrypt

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
    # Связь с пользователями (многие ко многим)
    members = db.relationship('User', secondary='membership', backref='departments')


# Модель для связи между пользователями и отделами
membership = db.Table('membership',
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                      db.Column('department_id', db.Integer, db.ForeignKey('department.id'), primary_key=True)
                      )


# Остальной код остается неизменным

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

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
    department = StringField('Department')
    position = StringField('Position')
    responsibilities = TextAreaField('Responsibilities')
    submit = SubmitField('Save Changes')


@app.route('/')
def main():
    return render_template('main.html')


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
def departments():
    all_departments = Department.query.all()
    return render_template('departments.html', departments=all_departments)


@app.route("/admin_departments", methods=['GET', 'POST'])
@login_required
def admin_departments():
    form = DepartmentForm()
    if form.validate_on_submit():
        department = Department(name=form.name.data, description=form.description.data)
        db.session.add(department)
        db.session.commit()
        flash('Отдел успешно добавлен!', 'success')
        return redirect(url_for('admin_departments'))
    departments = Department.query.all()
    return render_template('admin_departments.html', title='Администрирование отделов', form=form,
                           departments=departments)


@app.route("/admin_department_members/<int:department_id>", methods=['GET', 'POST'])
@login_required
def admin_department_members(department_id):
    department = Department.query.get_or_404(department_id)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user in department.members:
                department.members.remove(user)
                db.session.commit()
                flash('Пользователь успешно удален из отдела!', 'success')
            else:
                flash('Пользователь не состоит в этом отделе!', 'danger')
        return redirect(url_for('admin_department_members',
                                department_id=department.id))  # Перенаправляем на ту же страницу после удаления

    return render_template('admin_department_members.html', title='Управление членами отдела', department=department)


@app.route("/join_department/<int:department_id>", methods=['GET', 'POST'])
@login_required
def join_department(department_id):
    department = Department.query.get_or_404(department_id)
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
    department = Department.query.get_or_404(department_id)
    db.session.delete(department)
    db.session.commit()
    flash('Department has been deleted successfully!', 'success')
    return redirect(url_for('admin_departments'))


@app.route("/profile/<int:user_id>", methods=['GET', 'POST'])
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    form = EditProfileForm()

    if form.validate_on_submit():
        user.bio = form.bio.data
        user.passport_data = form.passport_data.data
        user.department = form.department.data
        user.position = form.position.data
        user.responsibilities = form.responsibilities.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')

    form.bio.data = user.bio
    form.passport_data.data = user.passport_data
    form.department.data = user.department
    form.position.data = user.position
    form.responsibilities.data = user.responsibilities

    return render_template('profile.html', title='Profile', form=form, user=user)


@app.route("/edit_profile", methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()

    if form.validate_on_submit():
        current_user.bio = form.bio.data
        current_user.passport_data = form.passport_data.data
        current_user.department = form.department.data
        current_user.position = form.position.data
        current_user.responsibilities = form.responsibilities.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))

    form.bio.data = current_user.bio
    form.passport_data.data = current_user.passport_data
    form.department.data = current_user.department
    form.position.data = current_user.position
    form.responsibilities.data = current_user.responsibilities

    return render_template('edit_profile.html', title='Edit Profile', form=form)


if __name__ == '__main__':
    app.run(debug=True)
