from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pickle
import os
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess  # To trigger the Tkinter application

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Load the ML model for gesture recognition (if required)
with open('model.pkl', 'rb') as file:
    model = pickle.load(file)

# Initialize SQLite database
def init_db():
    with sqlite3.connect('instance/user.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )''')
        conn.commit()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('input'))
    return redirect(url_for('login'))

# Register route (GET & POST)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        with sqlite3.connect('instance/user.db') as conn:
            try:
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'danger')
    return render_template('register.html')

# Login route (GET & POST)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('instance/user.db') as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user[2], password):  # Compare with hashed password
                session['user_id'] = user[0]
                session['username'] = user[1]
                return redirect(url_for('input'))  # Redirect to input page for gesture recognition
            else:
                flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Input route (Hand Gesture recognition page - accessible only after login)
@app.route('/input', methods=['GET', 'POST'])
def input():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect if not logged in
    
    if request.method == 'POST':
        # Here, you can start the Tkinter gesture recognition app from Flask
        subprocess.Popen(["python", "gesture_recognition.py"])  # Launch Tkinter application (as a separate process)
        return render_template('input.html', message="Gesture recognition has started!")
    
    return render_template('input.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
