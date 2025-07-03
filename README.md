🔐 SecureDoc – Secure File Vault (Encrypt & Decrypt with Login)

    An advanced Flask-based file vault that securely encrypts user files, supports login/registration, and includes an admin dashboard. Built with Flask, SQLAlchemy, Fernet, and Bootstrap.
	
	
🧠 Features

✅ Secure user registration & login using hashed passwords
✅ AES-level file encryption using Fernet before storing
✅ File decryption & download only after login
✅ Admin dashboard to view all users and uploaded files
✅ Role-based access (admin vs user)
✅ Responsive and modern UI using Bootstrap 5
✅ Alerts and validations for smooth UX
🛠️ Tech Stack
Category	Tech
Backend	Python, Flask
Database	SQLite with SQLAlchemy ORM
Frontend	HTML, Bootstrap 5
Auth & Roles	Flask-Login
Encryption	cryptography.fernet
Dev Tools	VS Code, Git, GitHub
🏗️ Project Structure

SecureDoc/
│
├── app.py                   # Main Flask app
├── templates/               # HTML UI templates
│   ├── layout.html
│   ├── login.html
│   ├── register.html
│   ├── index.html
│   ├── upload.html
│   └── admin.html
├── uploads/                 # Encrypted file storage
├── instance/securedoc.db    # SQLite DB file
├── static/                  # (optional) for custom CSS or JS
├── .venv/                   # Python virtual environment
├── README.md                # You are here
└── requirements.txt         # Python dependencies

⚙️ How to Run Locally
1. Clone the Repo

git clone https://github.com/yourusername/SecureDoc.git
cd SecureDoc

2. Set Up Virtual Environment

python3 -m venv .venv
source .venv/bin/activate  # or `.venv\\Scripts\\activate` on Windows
pip install -r requirements.txt

3. Run the App

python app.py

Access: http://127.0.0.1:5000

🧪 Default Admin Login:

    Username: admin

    Password: admin123

📦 requirements.txt

Flask
Flask-Login
Flask-SQLAlchemy
cryptography
Werkzeug

🛡️ Security Notes

    Passwords are hashed using generate_password_hash

    File contents are encrypted before storage using Fernet (AES)

    Admin-only access to sensitive data

📢 Contributing

If you'd like to contribute (e.g. add user profile pics, download logs, cloud storage integration), feel free to fork the repo and open a PR.
📄 License

MIT License – free to use for personal and commercial projects.
🙋‍♂️ About Me

👨‍💻 Aman Chaurasia – Developer & Cybersecurity Enthusiast
