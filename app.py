# qr-code-project/app.py

from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, session, Blueprint, send_file, make_response
)
import sqlite3
import qrcode
from io import BytesIO
import base64
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps 
import random
import string
from PIL import Image, ImageDraw, ImageFont 
import pandas as pd # Needed for Excel export

app = Flask(__name__)

# --- Configuration ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-this-insecure-default-key-please') 
DATABASE = 'attendance.db'
# --- !!! IMPORTANT: Update this path to your actual font file !!! ---
FONT_PATH = os.path.join(app.static_folder, 'fonts', 'YOUR_FONT_NAME.ttf') # Example path

# --- Database Setup ---
def get_db_connection():
    """Connects to the specific database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Return rows as dictionary-like objects
    # Enable foreign key support
    conn.execute("PRAGMA foreign_keys = ON") 
    return conn

def init_db():
    """Initializes the database schema."""
    conn = get_db_connection()
    cursor = conn.cursor() 

    # Create students table 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            course TEXT,
            qr_code TEXT,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0 -- 0 = No, 1 = Yes
        )
    ''')

    # Create events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            event_date TEXT NOT NULL,
            description TEXT
        )
    ''')
    
    # Create registrations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registrations (
            registration_id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL, 
            event_id INTEGER NOT NULL,   
            registration_time TEXT DEFAULT CURRENT_TIMESTAMP, 
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE, 
            FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE, 
            UNIQUE (student_id, event_id) 
        )
    ''')

    # Create attendance table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL, 
            event_id INTEGER NOT NULL, 
            date TEXT NOT NULL,
            time_in TEXT NOT NULL,
            status TEXT DEFAULT 'Present', 
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE, 
            FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE  
        )
    ''')
    
    # Add is_admin column if it doesn't exist (for upgrades)
    try:
        cursor.execute('ALTER TABLE students ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')
        print("Attempted to add is_admin column.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e): pass 
        else: conn.rollback(); conn.close(); raise e 

    conn.commit()
    conn.close()
    print("Database initialized/updated.")

# Run initialization when app starts
init_db()

# --- Helper Functions ---
def generate_qr_code(student_id_str):
    """Generates a base64 encoded QR code image string."""
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(student_id_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

def generate_captcha_text(length=6):
    """Generates a random alphanumeric string for CAPTCHA."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=length))

def generate_captcha_image(text):
    """Generates a PNG image of the CAPTCHA text."""
    font_path = "static/fonts/ChesalovaRegular-PV75m.ttf" # Use the configured path
    img = None # Initialize img
    try:
        if not os.path.exists(font_path):
             print(f"ERROR: CAPTCHA font not found at {font_path}. Using fallback image.")
             img = Image.new('RGB', (200, 50), color = (210, 210, 210))
             d = ImageDraw.Draw(img)
             d.text((10,10), "Font Not Found", fill=(255,0,0))
        else:
            font = ImageFont.truetype(font_path, 36) 
            
            # Determine text size accurately
            try:
                bbox = ImageDraw.Draw(Image.new('RGB',(1,1))).textbbox((0, 0), text, font=font, anchor='lt') # left, top anchor
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
                width, height = text_width + 40, text_height + 20
            except AttributeError: # Fallback for older Pillow textsize
                 print("Warning: Using legacy textsize. Bounding box calculation might be less accurate.")
                 text_width, text_height = ImageDraw.Draw(Image.new('RGB',(1,1))).textsize(text, font=font)
                 width, height = text_width + 40, text_height + 20

            img = Image.new('RGB', (width, height), color = (240, 240, 240)) 
            d = ImageDraw.Draw(img)
            d.text((20, 10), text, font=font, fill=(50, 50, 50)) 

            # Add simple noise lines
            for _ in range(random.randint(3, 6)): 
                x1, y1 = random.randint(0, width), random.randint(0, height)
                x2, y2 = random.randint(0, width), random.randint(0, height)
                line_color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
                d.line([(x1, y1), (x2, y2)], fill=line_color, width=1)

    except Exception as e: # Catch potential Pillow/Font errors
         print(f"ERROR generating CAPTCHA image: {e}. Using fallback.")
         if img is None: # Ensure img exists even if font loading failed early
              img = Image.new('RGB', (200, 50), color = (210, 210, 210))
              d = ImageDraw.Draw(img)
              d.text((10,10), "Image Error", fill=(255,0,0))

    buf = BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return buf

# --- Authorization Decorators ---
def admin_required(f):
    """Decorator to ensure user is logged in and is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'student_db_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url)) 
        if not session.get('is_admin'): # Check admin status stored in session
            flash('You do not have permission to access this administrative page.', 'danger')
            return redirect(url_for('student.student_dashboard')) 
        return f(*args, **kwargs) 
    return decorated_function

def student_login_required(f):
    """Decorator to ensure user is logged in (can be student or admin)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'student_db_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url)) 
        return f(*args, **kwargs)
    return decorated_function

# --- Context Processor ---
@app.context_processor
def inject_user_status():
    """Injects user login status and admin status into all templates."""
    user_info = None
    is_admin = False
    if 'student_db_id' in session:
        user_info = {'db_id': session['student_db_id'], 'name': session.get('student_name')} 
        is_admin = session.get('is_admin', False) 
    return dict(logged_in_user=user_info, is_user_admin=is_admin) 

# === Blueprint Definitions ===
auth_bp = Blueprint('auth', __name__) 
student_bp = Blueprint('student', __name__, url_prefix='/student')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# === Authentication Routes (Auth Blueprint) ===

@auth_bp.route('/captcha_image')
def captcha_image():
    """Generates and serves the CAPTCHA image."""
    captcha_code = generate_captcha_text()
    session['captcha_code'] = captcha_code
    session.modified = True 
    image_buffer = generate_captcha_image(captcha_code)
    response = make_response(send_file(image_buffer, mimetype='image/png'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles student self-registration with CAPTCHA."""
    if request.method == 'POST':
        user_captcha = request.form.get('captcha_input')
        correct_captcha = session.pop('captcha_code', None) 
        
        # Get form values early for re-rendering on error
        student_id_form = request.form.get('student_id','') 
        name_form = request.form.get('name','')
        email_form = request.form.get('email', '')
        course_form = request.form.get('course', '')

        if not user_captcha or not correct_captcha or user_captcha.upper() != correct_captcha.upper():
            flash('Incorrect CAPTCHA code. Please try again.', 'danger')
            return render_template('signup.html', is_signup_page=True, student_id=student_id_form, 
                                   name=name_form, email=email_form, course=course_form) 

        student_id = request.form['student_id'] 
        name = request.form['name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not student_id or not name or not password or not confirm_password:
            flash('Please fill out all required fields.', 'danger')
            return render_template('signup.html', is_signup_page=True, student_id=student_id, name=name, email=email_form, course=course_form)
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html', is_signup_page=True, student_id=student_id, name=name, email=email_form, course=course_form)
        if len(password) < 6:
             flash('Password must be at least 6 characters long.', 'danger')
             return render_template('signup.html', is_signup_page=True, student_id=student_id, name=name, email=email_form, course=course_form)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            existing_student = cursor.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id,)).fetchone()
            if existing_student:
                flash('That Student ID is already taken. Please choose another.', 'danger')
                return render_template('signup.html', is_signup_page=True, student_id=student_id, name=name, email=email_form, course=course_form) 
            
            hashed_password = generate_password_hash(password)
            qr_code = generate_qr_code(student_id) 

            cursor.execute('INSERT INTO students (student_id, name, email, course, qr_code, password_hash, is_admin) VALUES (?, ?, ?, ?, ?, ?, 0)', 
                           (student_id, name, email_form, course_form, qr_code, hashed_password))
            conn.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        except sqlite3.Error as e:
            flash(f'Database error during signup: {e}', 'danger')
            conn.rollback()
            return render_template('signup.html', is_signup_page=True, student_id=student_id, name=name, email=email_form, course=course_form)
        finally:
            if conn: conn.close()
            
    # GET Request
    return render_template('signup.html', is_signup_page=True)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login with CAPTCHA and session creation."""
    if request.method == 'POST':
        user_captcha = request.form.get('captcha_input')
        correct_captcha = session.pop('captcha_code', None) 

        if not user_captcha or not correct_captcha or user_captcha.upper() != correct_captcha.upper():
            flash('Incorrect CAPTCHA code. Please try again.', 'danger')
            session.clear() 
            return redirect(url_for('auth.login'))

        student_id_attempt = request.form.get('student_id')
        password_attempt = request.form.get('password') 

        if not student_id_attempt or not password_attempt:
            flash('Please enter both Student ID and Password.', 'warning')
            return redirect(url_for('auth.login'))

        conn = get_db_connection()
        user = None 
        try:
            user = conn.execute('SELECT id, name, password_hash, is_admin FROM students WHERE student_id = ?', 
                                   (student_id_attempt,)).fetchone()
        except sqlite3.Error as e:
             flash(f"Database error during login: {e}", "danger")
        finally:
            if conn: conn.close()

        if user and user['password_hash'] and check_password_hash(user['password_hash'], password_attempt):
            session.clear() 
            session['student_db_id'] = user['id'] 
            session['student_name'] = user['name']
            session['is_admin'] = bool(user['is_admin']) 
            session.permanent = True 
            flash(f"Welcome, {user['name']}!", 'success')
            if session['is_admin']: return redirect(url_for('admin.dashboard')) 
            else: return redirect(url_for('student.student_dashboard')) 
        else:
            session.clear() 
            flash('Invalid Student ID or Password.', 'danger') 
            return redirect(url_for('auth.login')) 

    # GET Request - Clear session before showing login page
    session.clear() 
    return render_template('login.html', is_login_page=True)

@auth_bp.route('/logout')
def logout():
    """Clears the session."""
    session.clear() 
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login')) 

# === Student Routes (Student Blueprint) ===

@student_bp.route('/') 
@student_login_required
def student_dashboard():
    """Displays dashboard for the logged-in student."""
    student_db_id = session['student_db_id']
    conn = get_db_connection()
    student = None
    try:
        student = conn.execute('SELECT * FROM students WHERE id = ?', (student_db_id,)).fetchone()
    except sqlite3.Error as e:
        flash(f"Database error fetching student data: {e}", "danger")
    finally:
        if conn: conn.close()

    if not student: 
        flash('Error retrieving student data. Logging out.', 'danger')
        return redirect(url_for('auth.logout'))
    return render_template('student_dashboard.html', student=student)

@student_bp.route('/events') 
@student_login_required
def list_available_events():
    """Lists events students can register for."""
    student_db_id = session['student_db_id']
    conn = get_db_connection()
    all_events = []
    registered_ids = set()
    try:
        all_events = conn.execute('SELECT * FROM events WHERE date(event_date) >= date("now") ORDER BY event_date ASC').fetchall() 
        registered_event_ids_rows = conn.execute('SELECT event_id FROM registrations WHERE student_id = ?', (student_db_id,)).fetchall()
        registered_ids = {row['event_id'] for row in registered_event_ids_rows}
    except sqlite3.Error as e:
        flash(f"Database error fetching events: {e}", 'danger')
    finally:
        if conn: conn.close()
    return render_template('available_events.html', events=all_events, registered_ids=registered_ids)

@student_bp.route('/register/<int:event_id>', methods=['POST']) 
@student_login_required
def register_action(event_id):
    """Registers the logged-in student for a specific event."""
    student_db_id = session['student_db_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        event_exists = cursor.execute('SELECT 1 FROM events WHERE event_id = ?', (event_id,)).fetchone()
        if not event_exists:
             flash("Event not found.", "danger")
             return redirect(url_for('student.list_available_events'))
        cursor.execute('INSERT OR IGNORE INTO registrations (student_id, event_id) VALUES (?, ?)', (student_db_id, event_id))
        conn.commit()
        if cursor.rowcount > 0: flash("Successfully registered for the event.", 'success')
        else: flash("Already registered for this event.", 'info')
    except sqlite3.Error as e:
        flash(f"Database error during registration: {e}", 'danger'); conn.rollback()
    finally:
        if conn: conn.close()
    return redirect(url_for('student.list_available_events'))

@student_bp.route('/unregister/<int:event_id>', methods=['POST']) 
@student_login_required
def unregister_action(event_id):
    """Unregisters the logged-in student from a specific event."""
    student_db_id = session['student_db_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM registrations WHERE student_id = ? AND event_id = ?', (student_db_id, event_id))
        conn.commit()
        if cursor.rowcount > 0: flash("Successfully unregistered from the event.", 'success')
        else: flash("You were not registered for this event.", 'info')
    except sqlite3.Error as e:
        flash(f"Database error during unregistration: {e}", 'danger'); conn.rollback()
    finally:
        if conn: conn.close()
    return redirect(url_for('student.list_available_events'))

# === Admin Routes (Admin Blueprint) ===

@admin_bp.route('/dashboard') 
@admin_required 
def dashboard():
    """Admin dashboard view."""
    conn = get_db_connection()
    students_count, events_count, recent_attendance, todays_attendance_count = 0, 0, [], 0
    try:
        students_count = conn.execute('SELECT COUNT(*) FROM students').fetchone()[0]
        events_count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        recent_attendance = conn.execute('''
            SELECT att.*, s.student_id, s.name, e.name as event_name 
            FROM attendance att JOIN students s ON att.student_id = s.id LEFT JOIN events e ON att.event_id = e.event_id
            ORDER BY att.date DESC, att.time_in DESC LIMIT 10
        ''').fetchall()
        today = datetime.now().strftime('%Y-%m-%d')
        todays_attendance_count = conn.execute('SELECT COUNT(*) FROM attendance WHERE date = ?', (today,)).fetchone()[0]
    except sqlite3.Error as e:
         flash(f"Database error loading dashboard: {e}", "danger")
    finally:
        if conn: conn.close()
    return render_template('dashboard.html', students_count=students_count, events_count=events_count,
                           recent_attendance=recent_attendance, todays_attendance_count=todays_attendance_count)

@admin_bp.route('/add_student', methods=['GET', 'POST']) 
@admin_required
def add_student():
    """Handles adding students via Admin interface."""
    is_admin_form = False # Default
    student_id_form = request.form.get('student_id', '')
    name_form = request.form.get('name', '')
    email_form = request.form.get('email', '')
    course_form = request.form.get('course', '')
        
    if request.method == 'POST':
        password = request.form.get('password') 
        is_admin_form = request.form.get('is_admin') == 'on' 

        if not student_id_form or not name_form or not password:
             flash('Student ID, Name, and Password are required for admin add.', 'danger')
             return render_template('add_student.html', student_id=student_id_form, name=name_form, email=email_form, course=course_form, is_admin_form=is_admin_form)
        if len(password) < 6:
             flash('Password must be at least 6 characters long.', 'danger')
             return render_template('add_student.html', student_id=student_id_form, name=name_form, email=email_form, course=course_form, is_admin_form=is_admin_form)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            existing = cursor.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id_form,)).fetchone()
            if existing:
                flash('Student ID already exists!', 'danger')
                return render_template('add_student.html', student_id=student_id_form, name=name_form, email=email_form, course=course_form, is_admin_form=is_admin_form) 
            
            hashed_password = generate_password_hash(password)
            qr_code = generate_qr_code(student_id_form)
            
            cursor.execute('''
                INSERT INTO students (student_id, name, email, course, qr_code, password_hash, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (student_id_form, name_form, email_form, course_form, qr_code, hashed_password, 1 if is_admin_form else 0))
            conn.commit()
            flash(f'Student {name_form} added successfully {"as Admin" if is_admin_form else ""}!', 'success')
        except sqlite3.Error as e:
            flash(f'Database error adding student: {e}', 'danger'); conn.rollback()
        finally:
            if conn: conn.close()
        return redirect(url_for('admin.dashboard')) 
    
    # GET request - pass default is_admin_form=False
    return render_template('add_student.html', is_admin_form=is_admin_form)


@admin_bp.route('/events') 
@admin_required
def manage_events():
    """Displays the admin page to list and add events."""
    conn = get_db_connection()
    events = []
    try:
        events = conn.execute('SELECT * FROM events ORDER BY event_date DESC').fetchall()
    except sqlite3.Error as e:
         flash(f"Database error fetching events: {e}", "danger")
    finally:
        if conn: conn.close()
    return render_template('events.html', events=events) 

@admin_bp.route('/add_event', methods=['POST']) 
@admin_required
def add_event():
    """Handles the submission of the new event form (by admin)."""
    event_name = request.form.get('event_name')
    event_date = request.form.get('event_date')
    description = request.form.get('description', '')

    if not event_name or not event_date:
        flash('Event Name and Date are required.', 'danger')
        return redirect(url_for('admin.manage_events'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO events (name, event_date, description) VALUES (?, ?, ?)',
                     (event_name, event_date, description))
        conn.commit()
        flash(f"Event '{event_name}' created successfully!", 'success')
    except sqlite3.Error as e:
        flash(f"Database error creating event: {e}", 'danger'); conn.rollback()
    finally:
        if conn: conn.close()
    return redirect(url_for('admin.manage_events'))

@admin_bp.route('/scan', methods=['GET', 'POST']) 
@admin_required 
def scan():
    """Handles QR code scanning and marks attendance IF student is registered for the active event."""
    if request.method == 'POST':
        student_id_scanned = request.form.get('student_id') 
        active_event_id = None # Initialize
        try:
            active_event_id = request.form.get('active_event_id', type=int) 
        except ValueError:
            flash('Invalid Event ID submitted.', 'danger'); return redirect(url_for('admin.scan'))

        if not active_event_id:
             flash('ERROR: No event was selected!', 'danger'); return redirect(url_for('admin.scan'))
        if not student_id_scanned:
             flash('ERROR: Scanned Student ID was missing!', 'danger'); return redirect(url_for('admin.scan'))

        conn = get_db_connection()
        cursor = conn.cursor()
        action_taken = None # Variable to track outcome
        flash_message = None
        flash_category = 'info' 

        try:
            # 1. Find student (Keep this)
            student = cursor.execute('SELECT id, name FROM students WHERE student_id = ?', (student_id_scanned,)).fetchone()
            if not student:
                action_taken = 'error'
                flash_message = f'Student ID {student_id_scanned} not found!'
                flash_category = 'danger'
            else:
                student_internal_id, student_name = student['id'], student['name']
                print(f"DEBUG SCAN: Found student - ID: {student_internal_id}, Name: {student_name}") 

                # 2. Check registration (Only if student found)
                if action_taken != 'error':
                    is_registered = cursor.execute('SELECT 1 FROM registrations WHERE student_id = ? AND event_id = ?', (student_internal_id, active_event_id)).fetchone()
                    if not is_registered:
                        action_taken = 'error'
                        event_info = cursor.execute('SELECT name FROM events WHERE event_id = ?', (active_event_id,)).fetchone()
                        event_name = event_info['name'] if event_info else f"ID {active_event_id}"
                        flash_message = f'ATTENDANCE FAILED: Student {student_name} ({student_id_scanned}) is NOT registered for event: {event_name}.'
                        flash_category = 'danger'
                    else:
                         print(f"DEBUG SCAN: Student {student_internal_id} IS registered for event {active_event_id}.")

                # 3. Check existing attendance (Only if student found and registered)
                if action_taken != 'error':
                    today = datetime.now().strftime('%Y-%m-%d')
                    print(f"DEBUG SCAN: Checking existing attendance for student {student_internal_id}, event {active_event_id}, date {today}") 
                    existing_attendance = cursor.execute('SELECT 1 FROM attendance WHERE student_id = ? AND event_id = ? AND date = ?', 
                                                         (student_internal_id, active_event_id, today)).fetchone()
                    
                    if existing_attendance:
                        print("DEBUG SCAN: Attendance already marked for today.")
                        flash_message = f'Attendance already marked for {student_name} today!'
                        flash_category = 'warning'
                    else:
                        print("DEBUG SCAN: No existing attendance found. Marking attendance.")
                        current_time = datetime.now().strftime('%H:%M:%S')
                        print(f"DEBUG SCAN: Inserting attendance at {current_time}")
                        cursor.execute('''
                            INSERT INTO attendance (student_id, event_id, date, time_in)
                            VALUES (?, ?, ?, ?)
                        ''', (student_internal_id, active_event_id, today, current_time))
                        conn.commit()
                        print("DEBUG SCAN: Attendance marked successfully.")
                        flash_message = f'Attendance Recorded for {student_name}!'
                        flash_category = 'success'
            
        except sqlite3.Error as e:
             print(f"DEBUG SCAN: Database error occurred: {e}") 
             action_taken = 'error'
             flash_message = f'Database error during scan: {e}'
             flash_category = 'danger'
             if conn: conn.rollback() 
        finally:
             print("DEBUG SCAN: Entering finally block.") 
             if conn: 
                 conn.close() 
                 print("DEBUG SCAN: Database connection closed.") 

        # --- Flash message AFTER try/finally, based on action_taken ---
        if flash_message:
            print(f"DEBUG SCAN: Flashing message: [{flash_category}] {flash_message}") # DEBUG
            flash(flash_message, flash_category)
        else:
             print("DEBUG SCAN: No message to flash.") # DEBUG

        print("DEBUG SCAN: Reached end of POST request, redirecting.") 
        return redirect(url_for('admin.scan'))  
    
    # GET Request
    conn = get_db_connection()
    events = []
    try:
        events = conn.execute("SELECT event_id, name, event_date FROM events ORDER BY event_date DESC").fetchall()
    except sqlite3.Error as e:
        flash(f"Database error fetching events for selection: {e}", "danger")
    finally:
        if conn: conn.close()
    return render_template('scan.html', events=events) 

@admin_bp.route('/attendance') 
@admin_required
def attendance():
    """Displays all attendance records (Admin view), filtered by search term."""
    search_term = request.args.get('search_term', '').strip() 
    conn = get_db_connection()
    records = []
    try:
        query = ''' SELECT att.*, s.student_id, s.name, s.course, e.name as event_name 
                    FROM attendance att JOIN students s ON att.student_id = s.id LEFT JOIN events e ON att.event_id = e.event_id '''
        params = []
        if search_term:
            query += ' WHERE (s.name LIKE ? OR s.student_id LIKE ?)'
            params.extend([f'%{search_term}%', f'%{search_term}%']) 
        query += ' ORDER BY att.date DESC, att.time_in DESC'
        records = conn.execute(query, params).fetchall()
    except sqlite3.Error as e:
         flash(f"Database error fetching attendance: {e}", "danger")
    finally:
        if conn: conn.close()
    return render_template('attendance.html', records=records, search_term=search_term) 

@admin_bp.route('/export_attendance')
@admin_required
def export_attendance():
    """Exports the filtered attendance list to an Excel file."""
    search_term = request.args.get('search_term', '').strip() 
    conn = get_db_connection()
    try:
        query = ''' SELECT att.date AS Date, att.time_in AS Time, s.student_id AS "Student ID", s.name AS Name, 
                           s.course AS Course, e.name as Event, att.status AS Status
                    FROM attendance att JOIN students s ON att.student_id = s.id LEFT JOIN events e ON att.event_id = e.event_id '''
        params = []
        if search_term:
            query += ' WHERE (s.name LIKE ? OR s.student_id LIKE ?)'
            params.extend([f'%{search_term}%', f'%{search_term}%'])
        query += ' ORDER BY att.date DESC, att.time_in DESC'
        
        records = conn.execute(query, params).fetchall()
        records_list = [dict(row) for row in records]
        
        if not records_list:
            flash("No attendance data to export.", "warning")
            return redirect(url_for('admin.attendance', search_term=search_term))

        # Generate Excel File using Pandas (Assumes pandas and openpyxl installed)
        df = pd.DataFrame(records_list)
        output_buffer = BytesIO()
        # Use ExcelWriter to potentially handle multiple sheets later or for styling
        with pd.ExcelWriter(output_buffer, engine='openpyxl') as writer:
             df.to_excel(writer, index=False, sheet_name='Attendance')
        output_buffer.seek(0)

        # Send the file
        return send_file(
            output_buffer,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'attendance_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        )
    except ImportError:
         flash("Excel export requires 'pandas' and 'openpyxl'. Please run 'pip install pandas openpyxl'", "danger")
         return redirect(url_for('admin.attendance', search_term=search_term))
    except sqlite3.Error as e:
        flash(f"Database error during export: {e}", "danger")
        return redirect(url_for('admin.attendance', search_term=search_term))
    finally:
        if conn: conn.close()

# === Register Blueprints ===
app.register_blueprint(auth_bp) 
app.register_blueprint(student_bp) 
app.register_blueprint(admin_bp) 

# === Root Route ===
@app.route('/')
def index():
    """Redirects user based on login status and role."""
    if 'student_db_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('student.student_dashboard'))
    else:
        return redirect(url_for('auth.login'))

# === App Run ===
if __name__ == '__main__':
    app.run(debug=True)