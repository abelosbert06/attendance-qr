import qrcode

def generate_student_qr(name, roll_no):
    # Create data string with parameters
    data = f"Name:{name},RollNo:{roll_no}"
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    # Create and save image
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(f"student_{roll_no}.png")
    print(f"QR code generated for {name} (Roll No: {roll_no})")

# Example usage
generate_student_qr("John Doe", "2023001")