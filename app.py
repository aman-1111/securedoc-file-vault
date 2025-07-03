from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cryptography.fernet import Fernet
import os
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize app
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'securedoc.db')

if not os.path.exists('uploads'):
    os.makedirs('uploads')
if not os.path.exists(app.instance_path):
    os.makedirs(app.instance_path)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Encryption Key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    uploaded_by = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    files = FileRecord.query.filter_by(uploaded_by=current_user.username).all()
    return render_template('index.html', files=files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as f:
            f.write(encrypted_data)
        record = FileRecord(filename=filename, uploaded_by=current_user.username)
        db.session.add(record)
        db.session.commit()
        flash('File encrypted and uploaded successfully')
        return redirect(url_for('index'))
    return render_template('upload.html')

@app.route('/download/<filename>')
@login_required
def download(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        response = app.response_class(
            decrypted_data,
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment;filename={filename}'}
        )
        return response
    except Exception as e:
        flash('Decryption failed.')
        return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('index'))
    users = User.query.all()
    files = FileRecord.query.all()
    return render_template('admin.html', users=users, files=files)

# Run App
if __name__ == '__main__':
    with app.app_context():
        db_path = os.path.join(app.instance_path, 'securedoc.db')
        if os.path.exists(db_path):
            os.remove(db_path)

        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin created: username=admin, password=admin123")

    app.run(debug=True)
