from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import qrcode
from io import BytesIO
import base64
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    course = db.Column(db.String(100))
    qr_code = db.Column(db.Text)
    attendances = db.relationship('Attendance', backref='student', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time_in = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='Present')

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def dashboard():
    students = Student.query.all()
    attendance_records = Attendance.query.order_by(Attendance.date.desc()).limit(10).all()
    return render_template('dashboard.html', students=students, attendance_records=attendance_records)

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        email = request.form['email']
        course = request.form['course']
        
        # Check if student already exists
        if Student.query.filter_by(student_id=student_id).first():
            flash('Student ID already exists!', 'danger')
            return redirect(url_for('add_student'))
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(student_id)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to base64 for storing in database
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_code_img = base64.b64encode(buffered.getvalue()).decode('utf-8')
        
        # Create new student
        new_student = Student(
            student_id=student_id,
            name=name,
            email=email,
            course=course,
            qr_code=qr_code_img
        )
        
        db.session.add(new_student)
        db.session.commit()
        
        flash('Student added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_student.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        student_id = request.form['student_id']
        
        student = Student.query.filter_by(student_id=student_id).first()
        if not student:
            flash('Student not found!', 'danger')
            return redirect(url_for('scan'))
        
        # Check if already marked attendance today
        today = datetime.now().strftime('%Y-%m-%d')
        existing_attendance = Attendance.query.filter_by(
            student_id=student.id,
            date=today
        ).first()
        
        if existing_attendance:
            flash('Attendance already marked for today!', 'warning')
            return redirect(url_for('scan'))
        
        # Record attendance
        current_time = datetime.now().strftime('%H:%M:%S')
        new_attendance = Attendance(
            student_id=student.id,
            date=today,
            time_in=current_time
        )
        
        db.session.add(new_attendance)
        db.session.commit()
        
        flash(f'Attendance recorded for {student.name}!', 'success')
        return redirect(url_for('scan'))
    
    return render_template('scan.html')

@app.route('/attendance')
def attendance():
    records = Attendance.query.order_by(Attendance.date.desc()).all()
    return render_template('attendance.html', records=records)

@app.route('/generate_qr/<student_id>')
def generate_qr(student_id):
    student = Student.query.filter_by(student_id=student_id).first()
    if not student:
        flash('Student not found!', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('generate.html', student=student)

if __name__ == '__main__':
    app.run(debug=True)