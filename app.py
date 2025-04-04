from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import qrcode
from io import BytesIO
import base64
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Database setup
def get_db_connection():
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            course TEXT,
            qr_code TEXT,
            password_hash TEXT NOT NULL  -- Add this line
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL, -- Changed from INTEGER to TEXT to match student_id type? Check consistency.
            date TEXT NOT NULL,
            time_in TEXT NOT NULL,
            status TEXT DEFAULT 'Present',
            FOREIGN KEY (student_id) REFERENCES students (id) -- Consider if Foreign Key should reference student_id (TEXT) or id (INTEGER)
        )
    ''')
    # Optional: If the table already exists, you might need to alter it
    try:
        conn.execute('ALTER TABLE students ADD COLUMN password_hash TEXT')
        print("Added password_hash column to students table.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            pass # Column already exists, ignore error
        else:
            raise e # Raise other operational errors
            
    conn.commit()
    conn.close()

init_db()

# Helper functions
def generate_qr_code(student_id):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(student_id)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

# Routes
@app.route('/')
def dashboard():
    conn = get_db_connection()
    students = conn.execute('SELECT * FROM students').fetchall()
    attendance = conn.execute('''
        SELECT attendance.*, students.student_id, students.name 
        FROM attendance 
        JOIN students ON attendance.student_id = students.id
        ORDER BY attendance.date DESC, attendance.time_in DESC
        LIMIT 10
    ''').fetchall()
    conn.close()
    return render_template('dashboard.html', students=students, attendance=attendance)

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        email = request.form['email']
        course = request.form['course']
        password = request.form['password'] # Get password from form

        # --- Input Validation (Basic Example) ---
        if not password:
             flash('Password cannot be empty!', 'danger')
             return redirect(url_for('add_student'))
        if len(password) < 6: # Example minimum length
             flash('Password must be at least 6 characters long.', 'danger')
             return redirect(url_for('add_student'))
        # --- End Validation ---

        conn = get_db_connection()
        existing = conn.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id,)).fetchone()
        if existing:
            flash('Student ID already exists!', 'danger')
            conn.close()
            # Make sure to render the template again, potentially passing back other entered values
            return render_template('add_student.html') 

        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        
        qr_code = generate_qr_code(student_id) # Assumes generate_qr_code function exists
        
        try:
            conn.execute('''
                INSERT INTO students (student_id, name, email, course, qr_code, password_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (student_id, name, email, course, qr_code, hashed_password)) # Add hashed_password
            conn.commit()
            flash('Student added successfully!', 'success')
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'danger')
            conn.rollback() # Roll back changes on error
        finally:
            conn.close()
            
        return redirect(url_for('dashboard'))
    
    # For GET request
    return render_template('add_student.html') # Render the add student form

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        student_id = request.form['student_id']
        
        conn = get_db_connection()
        student = conn.execute('SELECT * FROM students WHERE student_id = ?', (student_id,)).fetchone()
        if not student:
            flash('Student not found!', 'danger')
            conn.close()
            return redirect(url_for('scan'))
        
        today = datetime.now().strftime('%Y-%m-%d')
        existing = conn.execute('''
            SELECT 1 FROM attendance 
            WHERE student_id = ? AND date = ?
        ''', (student['id'], today)).fetchone()
        
        if existing:
            flash('Attendance already marked for today!', 'warning')
            conn.close()
            return redirect(url_for('scan'))
        
        current_time = datetime.now().strftime('%H:%M:%S')
        conn.execute('''
            INSERT INTO attendance (student_id, date, time_in)
            VALUES (?, ?, ?)
        ''', (student['id'], today, current_time))
        conn.commit()
        conn.close()
        
        flash(f'Attendance recorded for {student["name"]}!', 'success')
        return redirect(url_for('scan'))
    
    return render_template('scan.html')

@app.route('/attendance')
def attendance():
    conn = get_db_connection()
    records = conn.execute('''
        SELECT attendance.*, students.student_id, students.name, students.course
        FROM attendance 
        JOIN students ON attendance.student_id = students.id
        ORDER BY attendance.date DESC, attendance.time_in DESC
    ''').fetchall()
    conn.close()
    return render_template('attendance.html', records=records)

@app.route('/login', methods=['GET', 'POST']) 
def login(): 
    if request.method == 'POST':
        student_id_attempt = request.form['student_id']
        password_attempt = request.form['password'] 

        if not student_id_attempt or not password_attempt:
            flash('Please enter both Student ID and Password.', 'warning')
            return redirect(url_for('login'))

        conn = get_db_connection()
        student = conn.execute('SELECT * FROM students WHERE student_id = ?', 
                               (student_id_attempt,)).fetchone()
        conn.close()

        if student and check_password_hash(student['password_hash'], password_attempt):
            flash('Login successful!', 'success')
            # Optional: Use session here later
            return redirect(url_for('view_student', student_id=student['student_id']))
        else:
            flash('Invalid Student ID or Password.', 'danger') 
            return redirect(url_for('login')) 

    # For GET request
    return render_template('login.html')

@app.route('/student/<student_id>')
def view_student(student_id):
    conn = get_db_connection()
    student = conn.execute('SELECT * FROM students WHERE student_id = ?', (student_id,)).fetchone()
    attendance = conn.execute('''
        SELECT * FROM attendance 
        WHERE student_id = ?
        ORDER BY date DESC
    ''', (student['id'],)).fetchall()
    conn.close()
    
    if not student:
        flash('Student not found!', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('student.html', student=student, attendance=attendance)

if __name__ == '__main__':
    app.run(debug=True)