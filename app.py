import os
import secrets
from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from db import DatabaseManager
import sqlite3
from cryptography.fernet import Fernet
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo


# initializing  the flask application
app = Flask(__name__,template_folder='/Users/aacellular/Desktop/sonia/Projects/computer lab/templates')
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


#database and security configuration
db = SQLAlchemy(app)
database_manager = DatabaseManager()
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # it redirects to login for unauthorized users

# minimal user class for flask login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username
# loading user from flask-login from the database
@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(database_manager.db_name) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        if result:
            return User(result[0], result[1])
    return None
class DatabaseManager:
    def __init__(self, db_name='passwords.db'):
        self.db_name = db_name
        self._initialize_db()

    def _initialize_db(self):
    #create users and table password if not exists
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL        
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    username TEXT,
                    encrypted_password TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            conn.commit()
# inserting new user
    def create_user(self, username, password_hash, salt):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            ''', (username, password_hash, salt))
            conn.commit()
# validating credentials
    def verify_user(self, username, password_hash):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result and result[1] == password_hash:
                return result[0]  # Return user ID
            return None
# save encrypted password entry
    def store_password(self, user_id, service, username, encrypted_password):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (user_id, service, username, encrypted_password)
                VALUES (?, ?, ?, ?)
            ''', (user_id, service, username, encrypted_password))
            conn.commit()
# get all password for user
    def get_passwords(self, user_id):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, service, username, encrypted_password FROM passwords WHERE user_id = ?', (user_id,))
            return cursor.fetchall()


# classes defining the forms for registration forms, login forms and password entry forms

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PasswordForm(FlaskForm):
    service = StringField('Service', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = TextAreaField('Password', validators=[DataRequired()])
    submit = SubmitField('Add Password')
# route definitions
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        salt = secrets.token_bytes(16).hex()
        password_hash = generate_password_hash(password + salt)

        try:
            database_manager.create_user(username, password_hash, salt)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Username already exists.', 'danger')
    return render_template('register.html',form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
# checking against store credentials
        with sqlite3.connect(database_manager.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT salt, password_hash FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result:
                salt = result[0]
                password_hash = result[1]
                if check_password_hash(password_hash, password + salt):
                    user_id = database_manager.verify_user(username, password_hash)
                    if user_id:
                        login_user(User(user_id, username))
                        return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html',form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # showing saved password for loggedin user
    passwords = database_manager.get_passwords(current_user.id)
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    form = PasswordForm()
    if form.validate_on_submit():
        service = form.service.data
        username = form.username.data
        password = form.password.data

        # Encrypt the password before storing
        key = Fernet.generate_key()
        fernet = Fernet(key) # it will generate a random encryption key
        encrypted_password = fernet.encrypt(password.encode())

        database_manager.store_password(current_user.id, service, username, encrypted_password.decode())
        flash('Password added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_password.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(port=5001, debug =True, ssl_context='adhoc')  # Change to your desired port, runs app with http dev mode.


