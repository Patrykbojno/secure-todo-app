from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from bcrypt import hashpw, gensalt, checkpw
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
import os
import random
import smtplib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Temporary storage for tasks
tasks = []

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Task structure (id, description, due date, category, complete status)
task_id_counter = 1

# Load email credentials (used for 2FA)
from dotenv import load_dotenv
load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(150), nullable=True)  # Temporary storage for 6-digit token

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.String(50), nullable=True)
    priority = db.Column(db.String(10), nullable=True)
    completed = db.Column(db.Boolean, default=False)
    category = db.Column(db.String(100), nullable=True)  # Add category field here
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@app.route('/')
@login_required
def index():
    user_tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=user_tasks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email')  # Optional email field

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html')

        # Check if the email is already in use (if provided)
        if email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already linked to another account.', 'error')
                return render_template('register.html')

        # Hash the password and create a new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                return redirect('/')
            else:
                print("Password check failed!")  # Add logging to see what's wrong
        else:
            print(f"User {username} not found.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.cli.command('create_test_user')
def create_test_user():
    """Creates a test user for login."""
    username = 'testuser'
    password = 'password'
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print("Test user already exists!")
    else:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        test_user = User(username=username, password=hashed_password)
        db.session.add(test_user)
        db.session.commit()
        print(f"Test user created! Username: {username}, Password: {password}")

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        email = request.form['email']
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already linked to another account.')
            return render_template('settings.html')

        current_user.email = email
        db.session.commit()
        flash('Email updated successfully.')
        return redirect('/settings')

    return render_template('settings.html')

@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    new_email = request.form['email']
    
    # Check if email is already in use
    if User.query.filter_by(email=new_email).first():
        flash("This email is already in use. Please try a different one.", "error")
        return redirect('/settings')
    
    # Update the user's email
    current_user.email = new_email
    db.session.commit()
    flash("Email successfully updated!", "success")
    return redirect('/settings')

@app.route('/enable_2fa', methods=['POST'])
@login_required
def enable_2fa():
    if not current_user.email:
        flash("You need to add an email address before enabling 2FA.", "danger")
        return redirect(url_for('settings'))
    
    # Generate a random 6-digit token
    token = ''.join(random.choices('0123456789', k=6))
    
    # Hash the token using bcrypt and store it in the database
    hashed_token = hashpw(token.encode('utf-8'), gensalt()).decode('utf-8')
    current_user.otp = hashed_token
    db.session.commit()

    # Send the token via email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            subject = "Your To-Do App 2FA Code"
            body = f"Your verification code is: {token}"
            msg = f"Subject: {subject}\n\n{body}"
            server.sendmail(EMAIL_ADDRESS, current_user.email, msg)
        flash("Verification code sent to your email.", "info")
    except Exception as e:
        flash(f"Error sending email: {e}", "danger")
    
    return redirect(url_for('settings'))

@app.route('/verify_email', methods=['POST'])
@login_required
def verify_email():
    verification_code = request.form.get('verification_code')

    # Verify the token using bcrypt
    if current_user.otp and checkpw(verification_code.encode('utf-8'), current_user.otp.encode('utf-8')):
        current_user.email_verified = True
        current_user.otp = None  # Clear OTP after successful verification
        db.session.commit()
        flash("Your email is verified. 2FA is now enabled!", "success")
    else:
        flash("Invalid verification code. Please try again.", "danger")

    return redirect(url_for('settings'))

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    # Get form data
    task_description = request.form['task_description']
    due_date = request.form['due_date']
    category = request.form['category']
    priority = request.form['priority']
    
    # Create a new task instance associated with the logged-in user
    new_task = Task(
        task_name=task_description,
        due_date=due_date,
        priority=priority,
        category=category,
        completed=False,
        user_id=current_user.id  # Associate task with the logged-in user
    )
    
    # Save the new task to the database
    db.session.add(new_task)
    db.session.commit()
    
    return redirect(url_for('index'))


@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    task = Task.query.get(task_id)  # Retrieve the task from the database
    if task:
        db.session.delete(task)  # Delete the task from the database
        db.session.commit()  # Commit the deletion
    return redirect(url_for('index'))

@app.route('/toggle_complete/<int:task_id>', methods=['POST'])
def toggle_complete(task_id):
    task = Task.query.get(task_id)  # Retrieve the task from the database
    if task:
        task.completed = not task.completed  # Toggle the completion status
        db.session.commit()  # Commit the change to the database
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) 