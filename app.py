# qr-code-project/app.py

import random
import string
from PIL import Image, ImageDraw, ImageFont 
from flask import Flask, render_template, request, redirect, url_for, flash, session, Blueprint, send_file, make_response 
import sqlite3
import qrcode
from io import BytesIO
import base64
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps # Needed for decorators

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-prod') # Use env var or default

# == Captcha ==
def generate_captcha_text(length=6):
    #Generates a random alphanumeric string for CAPTCHA.
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=length))

FONT_PATH_PLACEHOLDER = 'static/fonts/BebasNeue.otf'

def generate_captcha_image(text):
    """Generates a PNG image of the CAPTCHA text."""
    try:
        # Verify font path exists
        font_path = FONT_PATH_PLACEHOLDER 
        if not os.path.exists(font_path):
             # Fallback if font not found - creates a basic error image
             print(f"ERROR: CAPTCHA font not found at {font_path}. Using fallback.")
             img = Image.new('RGB', (200, 50), color = (210, 210, 210))
             d = ImageDraw.Draw(img)
             d.text((10,10), "Font Not Found", fill=(255,0,0))
             font_path = None # Prevent further errors
        else:
            font = ImageFont.truetype(font_path, 36) # Load font
            
            # Determine text size to create appropriate image size
            # Use textbbox for more accurate size in newer Pillow versions
            try:
                text_bbox = ImageDraw.Draw(Image.new('RGB',(1,1))).textbbox((0, 0), text, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                text_height = text_bbox[3] - text_bbox[1]
                width = text_width + 40 # Add padding
                height = text_height + 20 # Add padding
            except AttributeError: # Fallback for older Pillow
                 text_width, text_height = ImageDraw.Draw(Image.new('RGB',(1,1))).textsize(text, font=font)
                 width = text_width + 40 # Add padding
                 height = text_height + 20 # Add padding


            img = Image.new('RGB', (width, height), color = (240, 240, 240)) # Light background
            d = ImageDraw.Draw(img)

            # Draw text with slight offset
            d.text((20, 10), text, font=font, fill=(50, 50, 50)) # Dark grey text

            # Add some simple noise/lines (optional, very basic anti-bot)
            for _ in range(random.randint(3, 6)): # Draw 3 to 6 lines
                x1, y1 = random.randint(0, width), random.randint(0, height)
                x2, y2 = random.randint(0, width), random.randint(0, height)
                line_color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
                d.line([(x1, y1), (x2, y2)], fill=line_color, width=1)
            # Add some random dots (pixels)
            # for _ in range(100):
            #    d.point((random.randint(0, width), random.randint(0, height)), fill=line_color)

    except ImportError:
         # Pillow might be missing ImageFont, create fallback image
         print("ERROR: Pillow ImageFont not available. Using fallback.")
         img = Image.new('RGB', (200, 50), color = (210, 210, 210))
         d = ImageDraw.Draw(img)
         d.text((10,10), "Pillow Error", fill=(255,0,0))

    # Save image to an in-memory buffer
    buf = BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return buf

# === Blueprint Definitions ===
auth_bp = Blueprint('auth', __name__) # For login, logout, signup
student_bp = Blueprint('student', __name__, url_prefix='/student') # Student routes prefixed with /student
admin_bp = Blueprint('admin', __name__, url_prefix='/admin') # Admin routes prefixed with /admin

# --- Add CAPTCHA Image Route (within Auth Blueprint) ---
@auth_bp.route('/captcha_image')
def captcha_image():
    """Generates and serves the CAPTCHA image."""
    # Generate random code
    captcha_code = generate_captcha_text()
    # Store it in session (case doesn't matter for check, but store original)
    session['captcha_code'] = captcha_code
    session.modified = True # Ensure session is saved

    # Generate the image
    image_buffer = generate_captcha_image(captcha_code)
    
    # Serve the image
    response = make_response(send_file(image_buffer, mimetype='image/png'))
    # Prevent caching of the CAPTCHA image
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# --- Database Setup ---
DATABASE = 'attendance.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor() 

    # Create students table - ADDED is_admin column
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
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE, -- Added ON DELETE CASCADE
            FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE, -- Added ON DELETE CASCADE
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
            FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE, -- Added ON DELETE CASCADE
            FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE  -- Added ON DELETE CASCADE
        )
    ''')
    
    # --- Attempt to add is_admin column to existing students table ---
    try:
        cursor.execute('ALTER TABLE students ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')
        print("Added is_admin column to students table.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
             pass # Column already exists, ignore error
        else:
            conn.rollback(); conn.close(); raise e # Raise other errors

    conn.commit()
    conn.close()
    print("Database initialized/updated with admin flag.")

# Run initialization
init_db()

# --- Helper Function ---
def generate_qr_code(student_id_str):
    """Generates a base64 encoded QR code image string."""
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(student_id_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

# --- Authorization Decorator ---
def admin_required(f):
    """Decorator to ensure user is logged in and is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'student_db_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login')) # Redirect to AUTH blueprint login

        student_db_id = session['student_db_id']
        conn = get_db_connection()
        # Check the is_admin flag for the logged-in user
        user = conn.execute('SELECT is_admin FROM students WHERE id = ?', (student_db_id,)).fetchone()
        conn.close()

        # If user not found or is_admin is not 1 (or True), deny access
        if not user or not user['is_admin']: 
            flash('You do not have permission to access this administrative page.', 'danger')
            # Redirect non-admins to their own dashboard
            return redirect(url_for('student.student_dashboard')) 
            
        return f(*args, **kwargs) # Proceed to the route function if admin
    return decorated_function

# --- Context Processor (Injects login status/info into all templates) ---
@app.context_processor
def inject_user_status():
    user_info = None
    is_admin = False
    if 'student_db_id' in session:
        user_info = {'db_id': session['student_db_id'], 'name': session.get('student_name')} 
        is_admin = session.get('is_admin', False) # Get admin status from session
    return dict(logged_in_user=user_info, is_user_admin=is_admin) # Pass both to templates


# === Authentication Routes (Auth Blueprint) ===

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # --- Get CAPTCHA input FIRST ---
        user_captcha = request.form.get('captcha_input')
        correct_captcha = session.pop('captcha_code', None) # Get code AND remove from session

        # --- Verify CAPTCHA ---
        if not user_captcha or not correct_captcha or user_captcha.upper() != correct_captcha.upper():
            flash('Incorrect CAPTCHA code. Please try again.', 'danger')
            # Re-render form, passing back non-sensitive data
            student_id = request.form.get('student_id','') # Use .get to avoid error if missing
            name = request.form.get('name','')
            email = request.form.get('email', '')
            course = request.form.get('course', '')
            # Don't pass passwords back to the template
            return render_template('signup.html', student_id=student_id, name=name, email=email, course=course)
        # --- End CAPTCHA Verification ---

        # --- CAPTCHA passed, now get other form data ---
        student_id = request.form['student_id'] # Can use [''] now as we expect them post-captcha
        name = request.form['name']
        email = request.form.get('email', '')
        course = request.form.get('course', '')
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not student_id or not name or not password or not confirm_password:
            flash('Please fill out all required fields.', 'danger')
            return render_template('signup.html', student_id=student_id, name=name, email=email, course=course)
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html', student_id=student_id, name=name, email=email, course=course)
        if len(password) < 6:
             flash('Password must be at least 6 characters long.', 'danger')
             return render_template('signup.html', student_id=student_id, name=name, email=email, course=course)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            existing_student = cursor.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id,)).fetchone()
            if existing_student:
                flash('That Student ID is already taken. Please choose another.', 'danger')
                return render_template('signup.html', student_id=student_id, name=name, email=email, course=course) 
            
            hashed_password = generate_password_hash(password)
            qr_code = generate_qr_code(student_id) 

            cursor.execute('''
                INSERT INTO students (student_id, name, email, course, qr_code, password_hash, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, 0) 
            ''', (student_id, name, email, course, qr_code, hashed_password))
            conn.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('auth.login'))

        except sqlite3.Error as e:
            flash(f'Database error during signup: {e}', 'danger')
            conn.rollback()
            return render_template('signup.html', student_id=student_id, name=name, email=email, course=course)
        finally:
            # Ensure connection is closed even if checks fail early
            if conn: 
                conn.close()
            
    # GET Request
    return render_template('signup.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Don't clear session on GET, only on failed POST attempt or logout
    
    if request.method == 'POST':
         # --- Get CAPTCHA input FIRST ---
        user_captcha = request.form.get('captcha_input')
        correct_captcha = session.pop('captcha_code', None) # Get code AND remove from session

         # --- Verify CAPTCHA ---
        if not user_captcha or not correct_captcha or user_captcha.upper() != correct_captcha.upper():
            flash('Incorrect CAPTCHA code. Please try again.', 'danger')
            session.clear() # Clear session on failed CAPTCHA attempt for login
            return redirect(url_for('auth.login'))
        # --- End CAPTCHA Verification ---

        # --- CAPTCHA passed, now get login credentials ---
        student_id_attempt = request.form['student_id']
        password_attempt = request.form['password'] 

        if not student_id_attempt or not password_attempt:
            flash('Please enter both Student ID and Password.', 'warning')
         
            return redirect(url_for('auth.login'))

        # --- Proceed with Database Check ---
        conn = get_db_connection()
        user = None # Initialize user
        try:
            user = conn.execute('SELECT id, name, password_hash, is_admin FROM students WHERE student_id = ?', 
                                   (student_id_attempt,)).fetchone()
        except sqlite3.Error as e:
             flash(f"Database error during login: {e}", "danger")
        finally:
            if conn:
                conn.close()

        # --- Check Credentials ---
        if user and user['password_hash'] and check_password_hash(user['password_hash'], password_attempt):
            # --- Login Success ---
            # Clear any old session data just in case before setting new keys
            session.clear() 
            session['student_db_id'] = user['id'] 
            session['student_name'] = user['name']
            session['is_admin'] = bool(user['is_admin']) 
            session.permanent = True 
            
            flash(f"Welcome, {user['name']}!", 'success')
            
            if session['is_admin']:
                return redirect(url_for('admin.dashboard')) 
            else:
                 return redirect(url_for('student.student_dashboard')) 
        else:
            # --- Login Failed ---
            session.clear() # Clear session on failed login attempt
            flash('Invalid Student ID or Password.', 'danger') 
            return redirect(url_for('auth.login')) 

    # --- GET Request ---
    # Clear any previous session data before showing login page
    session.clear() 
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """Clears the session."""
    session.clear() # Clear all session keys
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login')) # Redirect to login page

# === Student Routes (Student Blueprint) ===

# Decorator to ensure student is logged in (can be admin or regular student)
def student_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'student_db_id' not in session:
            flash('Please log in to access this page.', 'warning')
            # Redirect to the main login page under the auth blueprint
            return redirect(url_for('auth.login', next=request.url)) 
        return f(*args, **kwargs)
    return decorated_function

@student_bp.route('/') # Base route is now /student/
@student_login_required
def student_dashboard():
    """Displays dashboard for the logged-in student."""
    student_db_id = session['student_db_id']
    conn = get_db_connection()
    try:
        student = conn.execute('SELECT * FROM students WHERE id = ?', (student_db_id,)).fetchone()
    except sqlite3.Error as e:
        flash(f"Database error fetching student data: {e}", "danger")
        student = None
    finally:
        conn.close()

    if not student: # Should not happen normally
        flash('Error retrieving student data. Logging out.', 'danger')
        return redirect(url_for('auth.logout'))

    return render_template('student_dashboard.html', student=student)

@student_bp.route('/events') # Route is /student/events
@student_login_required
def list_available_events():
    """Lists events students can register for."""
    student_db_id = session['student_db_id']
    conn = get_db_connection()
    all_events = []
    registered_ids = set()
    try:
        all_events = conn.execute('SELECT * FROM events WHERE date(event_date) >= date("now") ORDER BY event_date ASC').fetchall() # Show only future events
        registered_event_ids_rows = conn.execute('SELECT event_id FROM registrations WHERE student_id = ?', (student_db_id,)).fetchall()
        registered_ids = {row['event_id'] for row in registered_event_ids_rows}
    except sqlite3.Error as e:
        flash(f"Database error fetching events: {e}", 'danger')
    finally:
        conn.close()
    return render_template('available_events.html', events=all_events, registered_ids=registered_ids)

@student_bp.route('/register/<int:event_id>', methods=['POST']) # Route is /student/register/<id>
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
        conn.close()
    return redirect(url_for('student.list_available_events'))

@student_bp.route('/unregister/<int:event_id>', methods=['POST']) # Route is /student/unregister/<id>
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
        conn.close()
    return redirect(url_for('student.list_available_events'))

# === Admin Routes (Admin Blueprint) ===

@admin_bp.route('/dashboard') # Route is /admin/dashboard
@admin_required # Protect this route
def dashboard():
    """Admin dashboard view."""
    conn = get_db_connection()
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
         students_count, events_count, recent_attendance, todays_attendance_count = 0, 0, [], 0
    finally:
        conn.close()
    return render_template('dashboard.html', students_count=students_count, events_count=events_count,
                           recent_attendance=recent_attendance, todays_attendance_count=todays_attendance_count)

@admin_bp.route('/add_student', methods=['GET', 'POST']) # Route is /admin/add_student
@admin_required
def add_student():
    """Handles adding students via Admin interface."""
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        email = request.form.get('email', '')
        course = request.form.get('course', '')
        password = request.form.get('password') 
        is_admin_form = request.form.get('is_admin') == 'on' # Checkbox value

        if not student_id or not name or not password:
             flash('Student ID, Name, and Password are required for admin add.', 'danger')
             return render_template('add_student.html', student_id=student_id, name=name, email=email, course=course, is_admin_form=is_admin_form)
        if len(password) < 6:
             flash('Password must be at least 6 characters long.', 'danger')
             return render_template('add_student.html', student_id=student_id, name=name, email=email, course=course, is_admin_form=is_admin_form)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            existing = cursor.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id,)).fetchone()
            if existing:
                flash('Student ID already exists!', 'danger')
                return render_template('add_student.html', student_id=student_id, name=name, email=email, course=course, is_admin_form=is_admin_form) 
            
            hashed_password = generate_password_hash(password)
            qr_code = generate_qr_code(student_id)
            
            cursor.execute('''
                INSERT INTO students (student_id, name, email, course, qr_code, password_hash, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (student_id, name, email, course, qr_code, hashed_password, 1 if is_admin_form else 0))
            conn.commit()
            flash(f'Student {name} added successfully {"as Admin" if is_admin_form else ""}!', 'success')
        except sqlite3.Error as e:
            flash(f'Database error adding student: {e}', 'danger'); conn.rollback()
        finally:
            conn.close()
        return redirect(url_for('admin.dashboard')) 
    return render_template('add_student.html')

@admin_bp.route('/events') # Route is /admin/events
@admin_required
def manage_events():
    """Displays the admin page to list and add events."""
    conn = get_db_connection()
    try:
        events = conn.execute('SELECT * FROM events ORDER BY event_date DESC').fetchall()
    except sqlite3.Error as e:
         flash(f"Database error fetching events: {e}", "danger"); events = []
    finally:
        conn.close()
    return render_template('events.html', events=events) 

@admin_bp.route('/add_event', methods=['POST']) # Route is /admin/add_event
@admin_required
def add_event():
    """Handles the submission of the new event form (by admin)."""
    event_name = request.form['event_name']
    event_date = request.form['event_date']
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
        conn.close()
    return redirect(url_for('admin.manage_events'))

@admin_bp.route('/scan', methods=['GET', 'POST']) # Route is /admin/scan
@admin_required # Assume only admins or designated operators scan
def scan():
    """Handles QR code scanning and marks attendance IF student is registered for the active event."""
    if request.method == 'POST':
        student_id_scanned = request.form.get('student_id') 
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
        try:
            student = cursor.execute('SELECT id, name FROM students WHERE student_id = ?', (student_id_scanned,)).fetchone()
            if not student:
                flash(f'Student ID {student_id_scanned} not found!', 'danger'); return redirect(url_for('admin.scan'))
            student_internal_id, student_name = student['id'], student['name']

            is_registered = cursor.execute('SELECT 1 FROM registrations WHERE student_id = ? AND event_id = ?', (student_internal_id, active_event_id)).fetchone()
            if not is_registered:
                event_info = cursor.execute('SELECT name FROM events WHERE event_id = ?', (active_event_id,)).fetchone()
                event_name = event_info['name'] if event_info else f"ID {active_event_id}"
                flash(f'ATTENDANCE FAILED: Student {student_name} ({student_id_scanned}) is NOT registered for event: {event_name}.', 'danger')
                return redirect(url_for('admin.scan'))

            today = datetime.now().strftime('%Y-%m-%d')
            existing_attendance = cursor.execute('SELECT 1 FROM attendance WHERE student_id = ? AND event_id = ? AND date = ?', (student_internal_id, active_event_id, today)).fetchone()
            if existing_attendance:
                flash(f'Attendance ALREADY marked for {student_name} for this event today!', 'warning'); return redirect(url_for('admin.scan'))
                
            current_time = datetime.now().strftime('%H:%M:%S')
            cursor.execute('INSERT INTO attendance (student_id, event_id, date, time_in) VALUES (?, ?, ?, ?)', (student_internal_id, active_event_id, today, current_time))
            conn.commit()
            flash(f'Attendance Recorded for {student_name}!', 'success')
        except sqlite3.Error as e:
             flash(f'Database error during scan: {e}', 'danger'); conn.rollback()
        finally:
             conn.close()
        return redirect(url_for('admin.scan')) 
    
    # GET Request
    conn = get_db_connection()
    try:
        events = conn.execute("SELECT event_id, name, event_date FROM events ORDER BY event_date DESC").fetchall()
    except sqlite3.Error as e:
        flash(f"Database error fetching events: {e}", "danger"); events = []
    finally:
        conn.close()
    return render_template('scan.html', events=events)

@admin_bp.route('/attendance') # Route is /admin/attendance
@admin_required
def attendance():
    """Displays all attendance records (Admin view)."""
    # TODO: Add filtering controls (by event, student, date range)
    conn = get_db_connection()
    try:
        records = conn.execute('''
            SELECT att.*, s.student_id, s.name, s.course, e.name as event_name 
            FROM attendance att JOIN students s ON att.student_id = s.id LEFT JOIN events e ON att.event_id = e.event_id
            ORDER BY att.date DESC, att.time_in DESC
        ''').fetchall()
    except sqlite3.Error as e:
         flash(f"Database error fetching attendance: {e}", "danger"); records = []
    finally:
        conn.close()
    return render_template('attendance.html', records=records)

# === Register Blueprints ===
app.register_blueprint(auth_bp) # No prefix for login/signup/logout
app.register_blueprint(student_bp) # Prefixed with /student
app.register_blueprint(admin_bp) # Prefixed with /admin

# === Root Route (Redirect based on login/admin status) ===
@app.route('/')
def index():
    if 'student_db_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('student.student_dashboard'))
    else:
        return redirect(url_for('auth.login'))


if __name__ == '__main__':
    app.run(debug=True) # Keep debug=True for development