import string
import sys

from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, login_user, LoginManager, current_user, logout_user
import os
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt

app = Flask(__name__)

bcrypt = Bcrypt(app)

basedir = os.path.abspath(os.path.dirname(__file__))

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')

app.config['SECRET_KEY'] = "secretkey"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Error:
    message = string

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(100), nullable = False)
    tasks = db.relationship('Task', backref = 'user')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.String(300), nullable = False)

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min = 4, max = 20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=100)],
                           render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username = username.data).first()
        if existing_user_username:
            raise ValidationError(
                'A user already exists with this name. Choose a different one'
                                )


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=100)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password. Please Try Again!")
        else:
            flash("Invalid Credentials. Please Try Again!")
    return render_template('login.html', form = form)

@app.route('/logout', methods = ['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    user = current_user
    tasks = user.tasks
    return render_template('dashboard.html', tasks=tasks, user = user)

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = LoginForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hashed_password)
        existing_user = User.query.filter_by(username=form.username.data).first()
        if (existing_user):
            print('\nAlready Exists Error!\n', file=sys.stderr)
            flash("That name is already taken, please choose another")
            return render_template('register.html', form = form)
        db.session.add(new_user)
        db.session.commit()
        flash("")
        return redirect(url_for('login'))
    return render_template('register.html', form = form)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    user = current_user
    tasks = user.tasks
    task = Task.query.filter_by(id=id).first()
    if task:
        Task.query.filter_by(id=id).delete()
        db.session.commit()
        return redirect(url_for('dashboard'))

@app.route('/dashboard/create', methods=['POST','GET'])
@login_required
def create():
    if request.method == 'POST':
        task = Task()
        user = current_user
        task.content = request.form['content']
        task.user = user
        if task:
            db.session.add(task)
            db.session.commit()
            return redirect('/dashboard')
    return "THERE WAS AN ERROR WHILE ADDING THE TASK!"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
