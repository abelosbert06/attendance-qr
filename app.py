# qr-code-project/app.py

from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import qrcode
from io import BytesIO
import base64
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os # Needed for a robust secret key later

app = Flask(__name__)

# --- !!! IMPORTANT: Set a strong, unique secret key !!! ---
# For development, you can use this, but change it for production
# A better way is: app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default-insecure-key-change-me')
app.secret_key = 'your_very_secret_key_needs_to_be_changed_and_kept_safe' 

# --- Database Setup ---
DATABASE = 'attendance.db'

def get_db_connection():
    """Connects to the specific database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Return rows as dictionary-like objects
    return conn

def init_db():
    """Initializes the database schema."""
    conn = get_db_connection()
    cursor = conn.cursor() 

    # Create students table (with password hash)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            course TEXT,
            qr_code TEXT,
            password_hash TEXT NOT NULL 
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
    
    # Create registrations table (Many-to-Many link)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registrations (
            registration_id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL, -- Foreign Key to students.id
            event_id INTEGER NOT NULL,   -- Foreign Key to events.event_id
            registration_time TEXT DEFAULT CURRENT_TIMESTAMP, 
            FOREIGN KEY (student_id) REFERENCES students (id),
            FOREIGN KEY (event_id) REFERENCES events (event_id),
            UNIQUE (student_id, event_id) -- Prevent duplicate registrations
        )
    ''')

    # Create attendance table (with event_id Foreign Key)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL, 
            event_id INTEGER NOT NULL, -- Records which event attendance belongs to
            date TEXT NOT NULL,
            time_in TEXT NOT NULL,
            status TEXT DEFAULT 'Present', 
            FOREIGN KEY (student_id) REFERENCES students (id),
            FOREIGN KEY (event_id) REFERENCES events (event_id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized/updated.")

# Run initialization
init_db()

# --- Helper Function ---
def generate_qr_code(student_id_str):
    """Generates a base64 encoded QR code image string."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(student_id_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

# --- Context Processor ---
@app.context_processor
def inject_user():
    """Injects user info into templates if logged in."""
    user_info = None
    if 'student_db_id' in session:
        user_info = {'db_id': session['student_db_id'], 'name': session.get('student_name')} 
    return dict(logged_in_user=user_info) # Use 'logged_in_user' in templates

# === Authentication Routes ===

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles student self-registration."""
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        email = request.form.get('email', '')
        course = request.form.get('course', '')
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Basic Validation
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
        try:
            existing_student = conn.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id,)).fetchone()
            if existing_student:
                flash('That Student ID is already taken. Please choose another.', 'danger')
                conn.close()
                return render_template('signup.html', student_id=student_id, name=name, email=email, course=course) 
            
            hashed_password = generate_password_hash(password)
            qr_code = generate_qr_code(student_id) 

            conn.execute('''
                INSERT INTO students (student_id, name, email, course, qr_code, password_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (student_id, name, email, course, qr_code, hashed_password))
            conn.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.Error as e:
            flash(f'Database error during signup: {e}', 'danger')
            conn.rollback()
            return render_template('signup.html', student_id=student_id, name=name, email=email, course=course)
        finally:
            conn.close()
            
    # GET Request
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles student login and session creation."""
    session.pop('student_db_id', None) 
    session.pop('student_name', None)

    if request.method == 'POST':
        student_id_attempt = request.form['student_id']
        password_attempt = request.form['password'] 

        if not student_id_attempt or not password_attempt:
            flash('Please enter both Student ID and Password.', 'warning')
            return redirect(url_for('login'))

        conn = get_db_connection()
        try:
            student = conn.execute('SELECT id, name, password_hash FROM students WHERE student_id = ?', 
                                   (student_id_attempt,)).fetchone()
        except sqlite3.Error as e:
             flash(f"Database error during login: {e}", "danger")
             student = None
        finally:
            conn.close()

        if student and student['password_hash'] and \
           check_password_hash(student['password_hash'], password_attempt):
            
            session['student_db_id'] = student['id'] 
            session['student_name'] = student['name']
            session.permanent = True 
            
            flash(f"Welcome, {student['name']}!", 'success')
            return redirect(url_for('student_dashboard')) 
        else:
            flash('Invalid Student ID or Password.', 'danger') 
            return redirect(url_for('login')) 

    # GET request
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clears the student session."""
    session.pop('student_db_id', None)
    session.pop('student_name', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# === Student Routes ===

@app.route('/student_dashboard')
def student_dashboard():
    """Displays dashboard for the logged-in student."""
    if 'student_db_id' not in session:
        flash('Please log in to access your dashboard.', 'warning')
        return redirect(url_for('login'))

    student_db_id = session['student_db_id']
    conn = get_db_connection()
    try:
        student = conn.execute('SELECT * FROM students WHERE id = ?', (student_db_id,)).fetchone()
        # TODO: Add fetching student's registrations or attendance here later if needed on dashboard
    except sqlite3.Error as e:
        flash(f"Database error fetching student data: {e}", "danger")
        student = None
    finally:
        conn.close()

    if not student:
        flash('Error retrieving student data. Please log in again.', 'danger')
        session.pop('student_db_id', None) 
        session.pop('student_name', None)
        return redirect(url_for('login'))

    return render_template('student_dashboard.html', student=student)


@app.route('/available_events')
def list_available_events():
    """Lists events students can register for."""
    if 'student_db_id' not in session:
        flash('Please log in to view events.', 'warning')
        return redirect(url_for('login'))

    student_db_id = session['student_db_id']
    conn = get_db_connection()
    all_events = []
    registered_ids = set()
    
    try:
        # Get all events (consider adding filters like date >= today later)
        all_events = conn.execute('SELECT * FROM events ORDER BY event_date DESC').fetchall()
        
        registered_event_ids_rows = conn.execute('''
            SELECT event_id FROM registrations WHERE student_id = ?
        ''', (student_db_id,)).fetchall()
        registered_ids = {row['event_id'] for row in registered_event_ids_rows}
        
    except sqlite3.Error as e:
        flash(f"Database error fetching events: {e}", 'danger')
    finally:
        conn.close()
            
    return render_template('available_events.html', 
                           events=all_events, 
                           registered_ids=registered_ids)


@app.route('/register_action/<int:event_id>', methods=['POST'])
def register_action(event_id):
    """Registers the logged-in student for a specific event."""
    if 'student_db_id' not in session:
        flash('Please log in to register for events.', 'warning')
        return redirect(url_for('login'))

    student_db_id = session['student_db_id']
    conn = get_db_connection()
    cursor = conn.cursor() # <-- Create a cursor
    
    try:
        event_exists = cursor.execute('SELECT 1 FROM events WHERE event_id = ?', (event_id,)).fetchone() # <-- Use cursor
        if not event_exists:
             flash("Event not found.", "danger")
             return redirect(url_for('list_available_events'))

        # Attempt to insert using the cursor
        cursor.execute('''
            INSERT OR IGNORE INTO registrations (student_id, event_id) 
            VALUES (?, ?)
        ''', (student_db_id, event_id)) # <-- Use cursor
        
        conn.commit() 
        
        # --- Check cursor.rowcount ---
        if cursor.rowcount > 0: # <-- Check if rows were affected
            flash("Successfully registered for the event.", 'success')
        else:
             flash("Already registered for this event.", 'info') 
        # --- End Check ---
        
    except sqlite3.Error as e:
        flash(f"Database error during registration: {e}", 'danger')
        conn.rollback() # Rollback on connection
    finally:
        conn.close() # Close connection
            
    return redirect(url_for('list_available_events'))


@app.route('/unregister_action/<int:event_id>', methods=['POST'])
def unregister_action(event_id):
    """Unregisters the logged-in student from a specific event."""
    if 'student_db_id' not in session:
        flash('Please log in to unregister from events.', 'warning')
        return redirect(url_for('login'))

    student_db_id = session['student_db_id']
    conn = get_db_connection()
    cursor = conn.cursor() # <-- Create a cursor
    
    try:
        # Execute DELETE using the cursor
        cursor.execute('''
            DELETE FROM registrations 
            WHERE student_id = ? AND event_id = ?
        ''', (student_db_id, event_id)) # <-- Use cursor
        
        conn.commit()
        
        # --- Check cursor.rowcount ---
        if cursor.rowcount > 0: # <-- Check if rows were affected
             flash("Successfully unregistered from the event.", 'success')
        else:
             flash("You were not registered for this event.", 'info')
        # --- End Check ---

    except sqlite3.Error as e:
        flash(f"Database error during unregistration: {e}", 'danger')
        conn.rollback() # Rollback on connection
    finally:
        conn.close() # Close connection

    return redirect(url_for('list_available_events'))

# === Admin / General Routes ===

@app.route('/')
def dashboard():
    """Admin dashboard view."""
    # TODO: Add admin login check here later
    conn = get_db_connection()
    try:
        students_count = conn.execute('SELECT COUNT(*) FROM students').fetchone()[0]
        # Update recent attendance to include event name
        recent_attendance = conn.execute('''
            SELECT att.*, s.student_id, s.name, e.name as event_name 
            FROM attendance att
            JOIN students s ON att.student_id = s.id
            LEFT JOIN events e ON att.event_id = e.event_id
            ORDER BY att.date DESC, att.time_in DESC
            LIMIT 10
        ''').fetchall()
        # Basic count for today - consider filtering by event later
        today = datetime.now().strftime('%Y-%m-%d')
        todays_attendance_count = conn.execute(
            'SELECT COUNT(*) FROM attendance WHERE date = ?', (today,)
        ).fetchone()[0]

    except sqlite3.Error as e:
         flash(f"Database error loading dashboard: {e}", "danger")
         students_count = 0
         recent_attendance = []
         todays_attendance_count = 0
    finally:
        conn.close()
        
    return render_template('dashboard.html', 
                           students_count=students_count, 
                           recent_attendance=recent_attendance,
                           todays_attendance_count=todays_attendance_count)

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    """Handles adding students via Admin interface."""
    # TODO: Add admin login check here later
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        email = request.form.get('email', '')
        course = request.form.get('course', '')
        # --- Get password from admin form ---
        password = request.form.get('password') 

        # --- Validation ---
        if not student_id or not name or not password:
             flash('Student ID, Name, and Password are required for admin add.', 'danger')
             # Pass back non-sensitive data
             return render_template('add_student.html', student_id=student_id, name=name, email=email, course=course)
        if len(password) < 6:
             flash('Password must be at least 6 characters long.', 'danger')
             return render_template('add_student.html', student_id=student_id, name=name, email=email, course=course)

        conn = get_db_connection()
        try:
            existing = conn.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id,)).fetchone()
            if existing:
                flash('Student ID already exists!', 'danger')
                conn.close()
                return render_template('add_student.html', student_id=student_id, name=name, email=email, course=course) 
            
            hashed_password = generate_password_hash(password)
            qr_code = generate_qr_code(student_id)
            
            conn.execute('''
                INSERT INTO students (student_id, name, email, course, qr_code, password_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (student_id, name, email, course, qr_code, hashed_password))
            conn.commit()
            flash('Student added successfully by admin!', 'success')
        except sqlite3.Error as e:
            flash(f'Database error adding student: {e}', 'danger')
            conn.rollback()
        finally:
            conn.close()
            
        return redirect(url_for('dashboard')) # Redirect to admin dashboard
    
    # GET request
    return render_template('add_student.html')


@app.route('/events')
def manage_events():
    """Displays the admin page to list and add events."""
    # TODO: Add admin login check here later
    conn = get_db_connection()
    try:
        events = conn.execute('SELECT * FROM events ORDER BY event_date DESC').fetchall()
    except sqlite3.Error as e:
         flash(f"Database error fetching events: {e}", "danger")
         events = []
    finally:
        conn.close()
    return render_template('events.html', events=events) 


@app.route('/add_event', methods=['POST'])
def add_event():
    """Handles the submission of the new event form (by admin)."""
    # TODO: Add admin login check here later
    if request.method == 'POST':
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        description = request.form.get('description', '')

        if not event_name or not event_date:
            flash('Event Name and Date are required.', 'danger')
            return redirect(url_for('manage_events'))

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO events (name, event_date, description) VALUES (?, ?, ?)',
                         (event_name, event_date, description))
            conn.commit()
            flash(f"Event '{event_name}' created successfully!", 'success')
        except sqlite3.Error as e:
            flash(f"Database error creating event: {e}", 'danger')
            conn.rollback()
        finally:
            conn.close()
                
    return redirect(url_for('manage_events'))


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Handles QR code scanning and marks attendance IF student is registered for the active event."""
    # TODO: Add admin/scanner role check here later?
    if request.method == 'POST':
        student_id_scanned = request.form.get('student_id') # ID string from QR code (hidden input)
        
        # --- Get Active Event ID from the form ---
        try:
            # Use .get with type=int for conversion and basic validation
            active_event_id = request.form.get('active_event_id', type=int) 
        except ValueError:
            flash('Invalid Event ID submitted.', 'danger')
            return redirect(url_for('scan'))

        if not active_event_id:
             flash('ERROR: No event was selected!', 'danger')
             return redirect(url_for('scan')) # Redirect back to allow selection
        # --- End getting Active Event ID ---

        if not student_id_scanned:
             flash('ERROR: Scanned Student ID was missing!', 'danger')
             return redirect(url_for('scan'))


        conn = get_db_connection()
        try:
            # 1. Find student's internal ID and name
            student = conn.execute('SELECT id, name FROM students WHERE student_id = ?', 
                                   (student_id_scanned,)).fetchone()
                                   
            if not student:
                flash(f'Student ID {student_id_scanned} not found in the system!', 'danger')
                return redirect(url_for('scan'))
                
            student_internal_id = student['id']
            student_name = student['name']

            # 2. Check if student is REGISTERED for the received active_event_id
            is_registered = conn.execute('''
                SELECT 1 FROM registrations 
                WHERE student_id = ? AND event_id = ? 
            ''', (student_internal_id, active_event_id)).fetchone() # Use active_event_id from form

            if not is_registered:
                event_info = conn.execute('SELECT name FROM events WHERE event_id = ?', (active_event_id,)).fetchone()
                event_name = event_info['name'] if event_info else f"ID {active_event_id}"
                flash(f'ATTENDANCE FAILED: Student {student_name} ({student_id_scanned}) is NOT registered for event: {event_name}.', 'danger')
                return redirect(url_for('scan'))

            # 3. Check if attendance already marked for this student/event/date
            today = datetime.now().strftime('%Y-%m-%d')
            existing_attendance = conn.execute('''
                SELECT 1 FROM attendance 
                WHERE student_id = ? AND event_id = ? AND date = ?
            ''', (student_internal_id, active_event_id, today)).fetchone() # Use active_event_id
            
            if existing_attendance:
                flash(f'Attendance ALREADY marked for {student_name} for this event today!', 'warning')
                return redirect(url_for('scan'))
                
            # 4. Record attendance
            current_time = datetime.now().strftime('%H:%M:%S')
            conn.execute('''
                INSERT INTO attendance (student_id, event_id, date, time_in)
                VALUES (?, ?, ?, ?)
            ''', (student_internal_id, active_event_id, today, current_time)) # Use active_event_id
            conn.commit()
            flash(f'Attendance Recorded for {student_name}!', 'success')
            
        except sqlite3.Error as e:
             flash(f'Database error during scan: {e}', 'danger')
             if conn: conn.rollback()
        finally:
             if conn: conn.close()

        return redirect(url_for('scan')) # Redirect back to scan page
    
    # === GET Request for Scan page ===
    conn = get_db_connection()
    try:
        # Fetch events where the date is today or in the future? Or just all? Fetching all for now.
        events = conn.execute("SELECT event_id, name, event_date FROM events ORDER BY event_date DESC").fetchall()
    except sqlite3.Error as e:
        flash(f"Database error fetching events for selection: {e}", "danger")
        events = []
    finally:
        conn.close()
        
    # Pass events list to the template for the dropdown
    return render_template('scan.html', events=events) 

@app.route('/attendance')
def attendance():
    """Displays all attendance records (Admin view)."""
    # TODO: Add admin login check here later
    # TODO: Add filtering by event
    conn = get_db_connection()
    try:
        records = conn.execute('''
            SELECT att.*, s.student_id, s.name, s.course, e.name as event_name 
            FROM attendance att
            JOIN students s ON att.student_id = s.id
            LEFT JOIN events e ON att.event_id = e.event_id
            ORDER BY att.date DESC, att.time_in DESC
        ''').fetchall()
    except sqlite3.Error as e:
         flash(f"Database error fetching attendance: {e}", "danger")
         records = []
    finally:
        conn.close()
        
    return render_template('attendance.html', records=records)

# Remove or repurpose the old /student/<student_id> route as it's replaced by /student_dashboard
# @app.route('/student/<student_id>') ...


if __name__ == '__main__':
    # Set debug=False for production
    app.run(debug=True)