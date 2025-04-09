# St. Joseph's College - QR Code Attendance Tracker

## Description

This web application provides a system for managing event attendance using QR codes specifically tailored for St. Joseph's College of Engineering, Chennai. 

**Key Features:**

* **Student Self-Signup:** Students can create their own accounts.
* **Secure Login:** User authentication with password hashing and a simple image CAPTCHA.
* **QR Code Generation:** Unique QR codes are generated for each student upon signup/creation.
* **Student Dashboard:** Logged-in students can view their details and QR code.
* **Event Management (Admin):** Admins can create and manage events (e.g., workshops, lectures).
* **Event Registration (Student):** Students can view available events and register/unregister themselves.
* **QR Code Scanning (Admin/Operator):** Admins can scan student QR codes using a webcam to mark attendance.
* **Attendance Verification:** The system verifies if a student is registered for the specific event before marking attendance.
* **Attendance Viewing (Admin):** Admins can view all attendance records.
* **Search & Export (Admin):** Admins can search the attendance log by student name/ID and export the filtered results to an Excel file.
* **Admin Roles:** Distinct administrative privileges for managing the system.

## Requirements

* Python 3.x
* pip (Python package installer)
* A web browser

## Installation

1.  **Clone or Download:** Get the project code onto your local machine.
2.  **Navigate to Project Directory:** Open your terminal or command prompt and change into the `qr-code-project` directory.
    ```bash
    cd path/to/qr-code-project
    ```
3.  **Create Virtual Environment:** It's highly recommended to use a virtual environment.
    ```bash
    python -m venv venv 
    ```
4.  **Activate Virtual Environment:**
    * On macOS/Linux: `source venv/bin/activate`
    * On Windows: `venv\Scripts\activate`
5.  **Install Dependencies:** Install all required packages using the `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```
6.   **Update Secret Key:** Find the line `app.secret_key = ...` and replace the default insecure key with a strong, random secret key (using environment variables is recommended for production).

## Running the Application

1.  **Ensure Virtual Environment is Active:** (See step 4 in Installation).
2.  **Run the App:** From the `qr-code-project` directory in your terminal, run:
    ```bash
    python app.py
    ```
    *(Alternatively, you might use `flask run`)*
3.  **Access the App:** Open your web browser and go to `http://127.0.0.1:5000` (or the address shown in your terminal). You should be redirected to the login page.

## Creating an Admin Account

Admin accounts allow access to manage events, add students manually, view all attendance, and scan QR codes.

**Method 1: Creating the *First* Admin Account (Manual Database Edit)**

You *must* use this method to create the very first admin user.

1.  **Run the App:** Start the Flask application (`python app.py`).
2.  **Sign Up:** Go to the signup page (`/signup`) in your browser and create a regular student account. Remember the Student ID and password you used.
3.  **Stop the App:** Stop the Flask application (`Ctrl+C` in the terminal).
4.  **Open Database:** Use a tool like **DB Browser for SQLite** (or another SQLite editor) to open the `attendance.db` file located in your `qr-code-project` directory.
5.  **Find User:** Go to the "Browse Data" tab (or equivalent) and select the `students` table. Find the row for the user account you just created.
6.  **Edit `is_admin` Flag:** Locate the `is_admin` column for that user. Double-click the cell (which should contain `0`) and change the value to `1`.
7.  **Save Changes:** Click the "Write Changes" or "Save" button in your database tool.
8.  **Close Database Tool.**
9.  **Restart the App:** Run `python app.py` again.
10. **Log In:** Log in using the credentials of the user you just promoted. You should now have access to the admin features and links in the navbar.

**Method 2: Creating *Additional* Admin Accounts (Using Admin Interface)**

Once you have at least one admin account (created using Method 1):

1.  **Log In:** Log in to the application as an existing administrator.
2.  **Navigate:** Go to the "Add Student" page (accessible via the admin links in the navbar, typically `/admin/add_student`).
3.  **Fill Details:** Enter the Student ID, Name, Password, and other details for the new user you want to create.
4.  **Check "Make Admin" Box:** Find the checkbox labeled "Make Admin User?" and **check it**.
5.  **Submit:** Click the "Add Student (Admin)" button. The new user will be created with admin privileges.

## Known Issues / Bugs

* **Incorrect Scan Flash Message:** When scanning a student's QR code for a specific event for the very first time on a given day, the system correctly records the attendance but incorrectly displays the flash message "Attendance ALREADY marked for this student for this event today!". Subsequent scans for the same student/event/day correctly show the "already marked" message. The success message ("Attendance Recorded...") seems to be skipped or overridden only on the initial successful scan. (Further debugging is needed to pinpoint the exact cause).
