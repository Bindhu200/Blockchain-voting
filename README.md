# Blockchain Voting System  
*(Healthcare-Inspired Secure Platform)*

A secure online voting platform utilizing **simulated blockchain technology** for complete transparency and tamper-proof records.  
Designed with security and usability in mind — similar to secure healthcare management systems.

## ✨ Features
- User registration & secure login (password hashing + JWT authentication)
- One vote per user (prevents double voting)
- Simulated blockchain with SHA-256 hashing, block chaining & tamper detection
- Real-time live results dashboard
- Modern, responsive, and professional UI/UX
- Secure password storage using PBKDF2-HMAC-SHA256

## 🛠️ Technologies Used
- **Backend**: Python, Flask  
- **Database**: SQLite (user credentials)  
- **Security**: cryptography (password hashing), PyJWT (authentication)  
- **Blockchain**: Custom implementation with hashlib (SHA-256)  
- **Frontend**: HTML5, CSS3, Jinja2 templating  

## 📸 Screenshots

### Home / Landing Page
![Home Page](screenshots/home.png)

### Login Page
![Login Page](screenshots/login.png)

### Dashboard (After Login + Voting)
![Dashboard](screenshots/dashboard.png)

## 🏃‍♂️ How to Run Locally

### 1. Clone the repository
```bash
git clone https://github.com/bindhu200/Blockchain-voting.git

cd Blockchain-voting

python app.py

Running on http://127.0.0.1:5000
