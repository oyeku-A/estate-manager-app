from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta
from functools import wraps
import csv
from io import StringIO, BytesIO
from sqlalchemy import inspect, or_
from werkzeug.utils import secure_filename
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io
import numpy as np
from collections import Counter
from supabase import create_client, Client
import uuid

# Load environment variables first
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-123')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_ANON_KEY')
)

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Roles
ROLE_USER = 'user'
ROLE_AGENT = 'agent'
ROLE_ADMIN = 'admin'

# Function to upload file to Supabase Storage
def upload_file_to_storage(file, bucket_name="property-images"):
    # Generate a unique filename
    file_extension = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4()}.{file_extension}"
    
    # Read the file content
    file_content = file.read()

    # Upload to Supabase Storage
    response = supabase.storage.from_(bucket_name).upload(
        path=unique_filename,
        file=file_content
    )
    
    if not response:
        return None
        
    # Get the public URL
    try:
        file_url = supabase.storage.from_(bucket_name).get_public_url(unique_filename)
        return file_url
    except Exception as url_error:
        return None
            

# Function to delete file from Supabase Storage
def delete_file_from_storage(file_path, bucket_name="property-images"):
    if file_path:
        filename = file_path.split('/')[-1]
        supabase.storage.from_(bucket_name).remove([filename])
    return True

# Decorators for role-based access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != ROLE_ADMIN:
            flash('You need admin privileges to access this page.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def agent_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in [ROLE_AGENT, ROLE_ADMIN]:
            flash('You need agent privileges to access this page.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=ROLE_USER)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Property Model
class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)  # Price in Naira
    location = db.Column(db.String(200), nullable=False)
    image_url = db.Column(db.String(500))
    agent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='available')
    property_type = db.Column(db.String(20), nullable=False, default='rent')  # 'rent' or 'sale'

# Booking Model
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    booking_date = db.Column(db.DateTime, nullable=False)
    duration_months = db.Column(db.Integer, nullable=True)
    move_in_date = db.Column(db.DateTime, nullable=True)
    move_out_date = db.Column(db.DateTime, nullable=True)
    special_requests = db.Column(db.Text, nullable=True)
    
    # Define relationships
    property = db.relationship('Property', backref='bookings')
    user = db.relationship('User', backref='bookings')
    payments = db.relationship('Payment', backref='booking', lazy=True)

# Payment Model
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # Amount in Naira
    payment_method = db.Column(db.String(50))
    transaction_id = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # pending, completed, failed
    payment_type = db.Column(db.String(20), nullable=False)  # rent, purchase
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Add maintenance status constants
MAINTENANCE_STATUS_PENDING = 'pending'
MAINTENANCE_STATUS_IN_PROGRESS = 'in_progress'
MAINTENANCE_STATUS_COMPLETED = 'completed'

# Maintenance Model
class Maintenance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    priority = db.Column(db.String(20), nullable=False, default='medium')
    estimated_cost = db.Column(db.Float)
    status = db.Column(db.String(20), nullable=False, default=MAINTENANCE_STATUS_PENDING)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationships
    property = db.relationship('Property', backref='maintenance_requests')
    reporter = db.relationship('User', foreign_keys=[reported_by], backref='reported_maintenance')

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    related_property_id = db.Column(db.Integer, db.ForeignKey('property.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)
    
    # Add relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    property = db.relationship('Property', backref='messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.template_filter('nl2br')
def nl2br(value):
    if not value:
        return ''
    return value.replace('\n', '<br>\n')

@app.context_processor
def utility_processor():
    def get_unread_messages_count():
        if not current_user.is_authenticated:
            return 0
        return Message.query.filter(
            Message.receiver_id == current_user.id,
            Message.read_at.is_(None)
        ).count()
    
    def get_pending_actions_count():
        if not current_user.is_authenticated:
            return 0
        
        count = 0
        if current_user.role in [ROLE_ADMIN, ROLE_AGENT]:
            # Count pending bookings for properties they manage
            if current_user.role == ROLE_ADMIN:
                pending_bookings = Booking.query.filter_by(status='pending').count()
            else:
                pending_bookings = Booking.query.join(Property).filter(
                    Property.agent_id == current_user.id,
                    Booking.status == 'pending'
                ).count()
            count += pending_bookings
        
        # Count pending payments for approved bookings
        if current_user.role == ROLE_USER:
            pending_payments = Booking.query.filter_by(
                user_id=current_user.id,
                status='approved'
            ).count()
            count += pending_payments
        
        return count

    return dict(
        get_unread_messages_count=get_unread_messages_count,
        get_pending_actions_count=get_pending_actions_count
    )

# Basic routes
@app.route('/')
def index():
    properties = Property.query.filter_by(status='available').all()
    return render_template('index.html', properties=properties)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(email=email, name=name, role=ROLE_USER)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == ROLE_ADMIN:
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == ROLE_AGENT:
        return redirect(url_for('agent_dashboard'))
    return redirect(url_for('user_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Property routes
@app.route('/property/<int:property_id>')
def property_detail(property_id):
    property = Property.query.get_or_404(property_id)
    agent = User.query.get(property.agent_id)
    return render_template('property_detail.html', property=property, agent=agent)

@app.route('/property/create', methods=['GET', 'POST'])
@login_required
def property_create():
    if current_user.role != ROLE_AGENT:
        flash('Only agents can create properties.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            image_url = None
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename and allowed_file(file.filename):
                    try:
                        image_url = upload_file_to_storage(file)
                        if not image_url:
                            flash('Error uploading image. Please check server logs.', 'error')
                            return redirect(url_for('property_create'))
                    except Exception as upload_error:
                        flash('Error during image upload process.', 'error')
                        return redirect(url_for('property_create'))

            property = Property(
                title=request.form.get('title'),
                description=request.form.get('description'),
                price=float(request.form.get('price')),
                location=request.form.get('location'),
                image_url=image_url,
                agent_id=current_user.id,
                property_type=request.form.get('property_type', 'rent')
            )
            db.session.add(property)
            db.session.commit()
            flash('Property created successfully!', 'success')
            return redirect(url_for('agent_dashboard'))
        except Exception as e:
            db.session.rollback()
            import traceback
            flash(f'Error creating property: {str(e)}', 'error')
            return redirect(url_for('property_create'))

    return render_template('property_form.html')

@app.route('/property/<int:property_id>/edit', methods=['GET', 'POST'])
@login_required
def property_edit(property_id):
    property = Property.query.get_or_404(property_id)
    
    if current_user.role != ROLE_AGENT or property.agent_id != current_user.id:
        flash('Only the agent who created this property can edit it.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename and allowed_file(file.filename):
                    # Delete old image if it exists
                    if property.image_url:
                        delete_file_from_storage(property.image_url)
                    
                    # Upload new image
                    new_image_url = upload_file_to_storage(file)
                    if new_image_url:
                        property.image_url = new_image_url
                    else:
                        flash('Error uploading new image.', 'error')
                        return redirect(url_for('property_edit', property_id=property_id))

            property.title = request.form.get('title')
            property.description = request.form.get('description')
            property.price = float(request.form.get('price'))
            property.location = request.form.get('location')
            property.property_type = request.form.get('property_type', 'rent')
            db.session.commit()
            flash('Property updated successfully!', 'success')
            return redirect(url_for('property_detail', property_id=property.id))
        except Exception as e:
            flash(f'Error updating property: {str(e)}', 'error')
            return redirect(url_for('property_edit', property_id=property_id))

    return render_template('property_form.html', property=property)

@app.route('/property/<int:property_id>/delete')
@login_required
def property_delete(property_id):
    property = Property.query.get_or_404(property_id)
    
    if current_user.role != ROLE_ADMIN and (current_user.role != ROLE_AGENT or property.agent_id != current_user.id):
        flash('You do not have permission to delete this property.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Delete image from storage if it exists
        if property.image_url:
            delete_file_from_storage(property.image_url)
        
        # Store the role before deletion for redirect
        is_admin = current_user.role == ROLE_ADMIN
        
        db.session.delete(property)
        db.session.commit()
        flash('Property deleted successfully!', 'success')
        
        return redirect(url_for('admin_dashboard' if is_admin else 'agent_dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting property: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard' if current_user.role == ROLE_ADMIN else 'agent_dashboard'))

# Dashboard routes
@app.route('/dashboard/admin')
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    properties = Property.query.order_by(Property.created_at.desc()).all()
    bookings = Booking.query.order_by(Booking.booking_date.desc()).all()
    return render_template('admin_dashboard.html', users=users, properties=properties, bookings=bookings)

@app.route('/dashboard/agent')
@agent_required
def agent_dashboard():
    properties = Property.query.filter_by(agent_id=current_user.id)\
        .order_by(Property.created_at.desc())\
        .all()
    bookings = Booking.query.join(Property)\
        .filter(Property.agent_id == current_user.id)\
        .order_by(Booking.booking_date.desc())\
        .all()
    return render_template('agent_dashboard.html', properties=properties, bookings=bookings)

@app.route('/dashboard/user')
@login_required
def user_dashboard():
    bookings = Booking.query.filter_by(user_id=current_user.id)\
        .order_by(Booking.booking_date.desc())\
        .all()
    return render_template('user_dashboard.html', bookings=bookings)

# Booking routes
@app.route('/property/<int:property_id>/book', methods=['POST'])
@login_required
def book_property(property_id):
    property = Property.query.get_or_404(property_id)
    
    # Check if property is available
    if property.status != 'available':
        flash('This property is not available for booking.', 'error')
        return redirect(url_for('property_detail', property_id=property_id))
    
    booking_date = datetime.strptime(request.form.get('booking_date'), '%Y-%m-%d')
    duration_months = int(request.form.get('duration_months', 12))
    
    # If admin is booking, they can assign an agent
    assigned_agent_id = None
    if current_user.role == ROLE_ADMIN:
        assigned_agent_id = request.form.get('assigned_agent_id')
        if not assigned_agent_id:
            # If no agent selected, assign to property's current agent
            assigned_agent_id = property.agent_id
    
    # Create booking
    booking = Booking(
        property_id=property_id,
        user_id=current_user.id,
        booking_date=booking_date,
        duration_months=duration_months,
        move_in_date=booking_date,
        move_out_date=booking_date + timedelta(days=30*duration_months),
        special_requests=request.form.get('special_requests'),
        status='pending'
    )
    
    if current_user.role == ROLE_ADMIN:
        # Auto-approve admin bookings
        booking.status = 'approved'
        property.status = 'pending_payment'
        
        # Notify assigned agent
        agent_notification = Message(
            sender_id=current_user.id,
            receiver_id=assigned_agent_id,
            subject=f"New Admin Booking Assigned - {property.title}",
            content=f"An admin booking has been automatically approved for {property.title}. You have been assigned to manage this booking.",
            related_property_id=property.id
        )
        db.session.add(agent_notification)
    else:
        # Regular user booking
        property.status = 'pending_approval'
        
        # Notify property agent
        agent_notification = Message(
            sender_id=current_user.id,
            receiver_id=property.agent_id,
            subject=f"New Booking Request - {property.title}",
            content=f"A new booking request has been submitted for {property.title}. Please review and approve/reject the booking.",
            related_property_id=property.id
        )
        db.session.add(agent_notification)
    
    db.session.add(booking)
    
    try:
        db.session.commit()
        if current_user.role == ROLE_ADMIN:
            flash('Admin booking created and automatically approved. Assigned agent has been notified.', 'success')
        else:
            flash('Booking request submitted successfully! Please wait for agent approval.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error submitting booking request: {str(e)}', 'error')
    
    return redirect(url_for('user_dashboard'))

@app.route('/booking/<int:booking_id>/approve')
@agent_required
def approve_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    property = Property.query.get(booking.property_id)
    
    if property.agent_id != current_user.id and current_user.role != ROLE_ADMIN:
        flash('You can only approve bookings for your properties.', 'error')
        return redirect(url_for('agent_dashboard'))
    
    # Check if property is already rented/sold
    if property.status not in ['available', 'pending_approval']:
        flash('This property is no longer available for booking.', 'error')
        return redirect(url_for('agent_dashboard'))
    
    # Update booking status
    booking.status = 'approved'
    old_status = property.status
    property.status = 'pending_payment'
    
    # Reject all other pending bookings for this property
    other_bookings = Booking.query.filter(
        Booking.property_id == property.id,
        Booking.id != booking.id,
        Booking.status == 'pending'
    ).all()
    
    notifications = []
    
    # Create notifications for rejected bookings
    for other_booking in other_bookings:
        other_booking.status = 'rejected'
        notifications.append(Message(
            sender_id=current_user.id,
            receiver_id=other_booking.user_id,
            subject=f"Booking Rejected - {property.title}",
            content=f"We regret to inform you that your booking request for {property.title} has been rejected as another booking has been approved.",
            related_property_id=property.id
        ))
    
    # Notify the user of approval
    notifications.append(Message(
        sender_id=current_user.id,
        receiver_id=booking.user_id,
        subject=f"Booking Approved - {property.title}",
        content=f"Your booking request for {property.title} has been approved. Please proceed with the payment to secure your booking.",
        related_property_id=property.id
    ))
    
    # Notify admin of the status change
    admin_users = User.query.filter_by(role=ROLE_ADMIN).all()
    for admin in admin_users:
        notifications.append(Message(
            sender_id=current_user.id,
            receiver_id=admin.id,
            subject=f"Property Status Updated - {property.title}",
            content=f"Property status changed from {old_status} to {property.status}. Booking has been approved by {current_user.name}.",
            related_property_id=property.id
        ))
    
    # Add all notifications
    for notification in notifications:
        db.session.add(notification)
    
    try:
        db.session.commit()
        flash('Booking approved and all notifications sent.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating booking status: {str(e)}', 'error')
    
    return redirect(url_for('agent_dashboard'))

@app.route('/booking/<int:booking_id>/reject')
@agent_required
def reject_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    property = Property.query.get(booking.property_id)
    
    if property.agent_id != current_user.id and current_user.role != ROLE_ADMIN:
        flash('You can only reject bookings for your properties.', 'error')
        return redirect(url_for('agent_dashboard'))
    
    # Update booking status
    old_status = booking.status
    booking.status = 'rejected'
    
    notifications = []
    
    # If this was the only pending booking, make property available again
    if not Booking.query.filter(
        Booking.property_id == property.id,
        Booking.status.in_(['pending', 'approved'])
    ).first():
        old_property_status = property.status
        property.status = 'available'
        
        # Notify admin of property status change
        admin_users = User.query.filter_by(role=ROLE_ADMIN).all()
        for admin in admin_users:
            notifications.append(Message(
                sender_id=current_user.id,
                receiver_id=admin.id,
                subject=f"Property Status Updated - {property.title}",
                content=f"Property status changed from {old_property_status} to available. All bookings have been processed.",
                related_property_id=property.id
            ))
    
    # Notify the user of rejection
    notifications.append(Message(
        sender_id=current_user.id,
        receiver_id=booking.user_id,
        subject=f"Booking Rejected - {property.title}",
        content=f"We regret to inform you that your booking request for {property.title} has been rejected.",
        related_property_id=property.id
    ))
    
    # Add all notifications
    for notification in notifications:
        db.session.add(notification)
    
    try:
        db.session.commit()
        flash('Booking rejected and all notifications sent.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating booking status: {str(e)}', 'error')
    
    return redirect(url_for('agent_dashboard'))

@app.route('/user/<int:user_id>/role', methods=['POST'])
@admin_required
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    # Validate role
    if new_role not in [ROLE_USER, ROLE_AGENT, ROLE_ADMIN]:
        flash('Invalid role specified.')
        return redirect(url_for('admin_dashboard'))
    
    # Prevent changing own role
    if user.id == current_user.id:
        flash('You cannot change your own role.')
        return redirect(url_for('admin_dashboard'))
    
    user.role = new_role
    db.session.commit()
    flash(f'User role updated to {new_role} successfully!')
    return redirect(url_for('admin_dashboard'))

# Report routes
@app.route('/reports/properties')
@admin_required
def property_report():
    return generate_property_report()

@app.route('/reports/bookings')
@admin_required
def booking_report():
    return generate_booking_report()

@app.route('/reports/maintenance')
@admin_required
def maintenance_report():
    return generate_maintenance_report()

# Payment routes
@app.route('/booking/<int:booking_id>/process-payment', methods=['POST'])
@login_required
def process_payment(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    property = Property.query.get(booking.property_id)
    payment = Payment.query.filter_by(booking_id=booking.id).first()
    
    if not payment:
        flash('Payment record not found.', 'error')
        return redirect(url_for('user_dashboard'))
    
    if booking.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('user_dashboard'))
    
    if booking.status not in ['approved', 'pending_payment']:
        flash('This booking is not ready for payment.', 'error')
        return redirect(url_for('user_dashboard'))
    
    payment_method = request.form.get('payment_method')
    if not payment_method:
        flash('Please select a payment method.', 'error')
        return redirect(url_for('payment_status', booking_id=booking.id))
    
    # Update payment record
    payment.payment_method = payment_method
    payment.status = 'completed'  # In a real app, this would be pending until payment confirmation
    payment.transaction_id = f'TXN_{datetime.now().strftime("%Y%m%d%H%M%S")}_{booking.id}'
    
    # Update booking and property status
    booking.status = 'paid'
    property.status = 'rented' if property.property_type == 'rent' else 'sold'
    
    # Create notification for the agent
    notification = Message(
        sender_id=current_user.id,
        receiver_id=property.agent_id,
        subject=f"Payment Received - {property.title}",
        content=f"Payment of ₦{payment.amount:,.2f} has been received for {property.title}. The property is now marked as {property.status}.",
        related_property_id=property.id
    )
    db.session.add(notification)
    
    try:
        db.session.commit()
        flash('Payment processed successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing payment: {str(e)}', 'error')
        return redirect(url_for('payment_status', booking_id=booking.id))
    
    return redirect(url_for('user_dashboard'))

@app.route('/booking/<int:booking_id>/payment', methods=['GET', 'POST'])
@login_required
def payment_status(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    property = Property.query.get(booking.property_id)
    
    if booking.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('user_dashboard'))
    
    if booking.status not in ['approved', 'pending_payment']:
        flash('This booking is not ready for payment.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Calculate payment amount
    if property.property_type == 'rent':
        amount = property.price * booking.duration_months
    else:
        amount = property.price
    
    # Get existing payment or create new one
    payment = Payment.query.filter_by(booking_id=booking.id).first()
    if not payment:
        payment = Payment(
            booking_id=booking.id,
            amount=amount,
            payment_method='pending',
            status='pending',
            transaction_id=f'TXN_{datetime.now().strftime("%Y%m%d%H%M%S")}_{booking.id}',
            payment_type='rent' if property.property_type == 'rent' else 'purchase'
        )
        db.session.add(payment)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating payment record: {str(e)}', 'error')
            return redirect(url_for('user_dashboard'))
    
    return render_template('payment_form.html', 
                         booking=booking, 
                         property=property, 
                         payment=payment)

# Maintenance routes
@app.route('/maintenance/report', methods=['GET', 'POST'])
@login_required
def report_maintenance():
    if request.method == 'POST':
        property_id = request.form.get('property_id')
        property = Property.query.get_or_404(property_id)
        
        # Check if property is for rent and currently rented
        if property.property_type != 'rent' or property.status != 'rented':
            flash('Maintenance requests can only be submitted for rented properties.', 'error')
            return redirect(url_for('maintenance_list'))
        
        # Check if user owns or rents the property
        if current_user.role == ROLE_USER:
            bookings = Booking.query.filter_by(
                user_id=current_user.id,
                property_id=property_id,
                status='paid'
            ).first()
            if not bookings:
                flash('You can only report maintenance for properties you are renting.', 'error')
                return redirect(url_for('maintenance_list'))
        elif current_user.role == ROLE_AGENT and property.agent_id != current_user.id:
            flash('You can only report maintenance for your properties.', 'error')
            return redirect(url_for('maintenance_list'))
        
        maintenance = Maintenance(
            property_id=property_id,
            title=request.form.get('title'),
            description=request.form.get('description'),
            reported_by=current_user.id,
            priority=request.form.get('priority', 'medium'),
            estimated_cost=float(request.form.get('estimated_cost', 0))
        )
        db.session.add(maintenance)
        
        try:
            db.session.commit()
            # Send notifications
            send_maintenance_notification(maintenance, 'new')
            db.session.commit()
            flash('Maintenance request submitted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting maintenance request: {str(e)}', 'error')
        
        return redirect(url_for('maintenance_list'))
    
    # For GET request, show form with filtered properties
    if current_user.role == ROLE_ADMIN:
        # Admin sees all rented properties
        properties = Property.query.filter_by(
            property_type='rent',
            status='rented'
        ).all()
    elif current_user.role == ROLE_AGENT:
        # Agent sees their rented properties
        properties = Property.query.filter_by(
            agent_id=current_user.id,
            property_type='rent',
            status='rented'
        ).all()
    else:  # Regular user
        # Get properties user is currently renting
        current_date = datetime.utcnow()
        booked_properties = Property.query.join(Booking).filter(
            Property.property_type == 'rent',
            Property.status == 'rented',
            Booking.user_id == current_user.id,
            Booking.status == 'paid',
            Booking.move_in_date <= current_date,
            Booking.move_out_date >= current_date
        ).all()
        properties = booked_properties
    
    return render_template('maintenance_form.html', properties=properties)

@app.route('/maintenance')
@login_required
def maintenance_list():
    if current_user.role == ROLE_ADMIN:
        # Admin sees all maintenance tasks for rented properties
        maintenance_tasks = Maintenance.query\
            .join(Property)\
            .filter(Property.property_type == 'rent')\
            .order_by(Maintenance.created_at.desc())\
            .all()
    elif current_user.role == ROLE_AGENT:
        # Agent sees maintenance tasks for their rented properties
        property_ids = [p.id for p in Property.query.filter_by(
            agent_id=current_user.id,
            property_type='rent'
        )]
        maintenance_tasks = Maintenance.query\
            .filter(Maintenance.property_id.in_(property_ids))\
            .order_by(Maintenance.created_at.desc())\
            .all()
    else:
        # User sees maintenance tasks for properties they rent
        maintenance_tasks = Maintenance.query\
            .join(Property)\
            .join(Booking)\
            .filter(
                Property.property_type == 'rent',
                Booking.user_id == current_user.id,
                Booking.status == 'paid'
            )\
            .order_by(Maintenance.created_at.desc())\
            .all()
    
    return render_template('maintenance_list.html', maintenance_tasks=maintenance_tasks)

@app.route('/maintenance/<int:task_id>/update', methods=['POST'])
@agent_required
def update_maintenance(task_id):
    task = Maintenance.query.get_or_404(task_id)
    property = Property.query.get(task.property_id)
    
    # Verify property is for rent
    if property.property_type != 'rent':
        flash('Maintenance can only be updated for rental properties.', 'error')
        return redirect(url_for('maintenance_list'))
    
    if property.agent_id != current_user.id and current_user.role != ROLE_ADMIN:
        flash('Unauthorized access.')
        return redirect(url_for('maintenance_list'))
    
    new_status = request.form.get('status')
    if new_status not in [MAINTENANCE_STATUS_PENDING, MAINTENANCE_STATUS_IN_PROGRESS, MAINTENANCE_STATUS_COMPLETED]:
        flash('Invalid status provided.', 'error')
        return redirect(url_for('maintenance_list'))
    
    old_status = task.status
    task.status = new_status
    if new_status == MAINTENANCE_STATUS_COMPLETED and old_status != MAINTENANCE_STATUS_COMPLETED:
        task.completed_at = datetime.utcnow()
    elif new_status != MAINTENANCE_STATUS_COMPLETED:
        task.completed_at = None
    
    try:
        db.session.commit()
        # Send notification about status update
        if old_status != task.status:
            send_maintenance_notification(task, 'status_update')
            db.session.commit()
        flash('Maintenance task updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating maintenance task: {str(e)}', 'error')
    
    return redirect(url_for('maintenance_list'))

# Messaging routes
@app.route('/messages')
@login_required
def message_list():
    # Get unread messages first, then read messages, both ordered by creation date
    received_messages = Message.query\
        .filter_by(receiver_id=current_user.id)\
        .order_by(Message.read_at.is_(None).desc(), Message.created_at.desc())\
        .all()
    
    sent_messages = Message.query\
        .filter_by(sender_id=current_user.id)\
        .order_by(Message.created_at.desc())\
        .all()
    
    return render_template('message_list.html', 
                         received_messages=received_messages, 
                         sent_messages=sent_messages)

@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id')
        subject = request.form.get('subject')
        content = request.form.get('content')
        property_id = request.form.get('property_id') or None
        
        if not all([receiver_id, subject, content]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('send_message'))
        
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            subject=subject,
            content=content,
            related_property_id=property_id
        )
        db.session.add(message)
        db.session.commit()
        
        flash('Message sent successfully!', 'success')
        return redirect(url_for('message_list'))
    
    # For GET request, get list of users and properties
    users = User.query.filter(User.id != current_user.id).all()
    properties = Property.query.all()
    return render_template('message_form.html', users=users, properties=properties)

@app.route('/messages/<int:message_id>')
@login_required
def view_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.receiver_id != current_user.id and message.sender_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('message_list'))
    
    # Mark message as read if current user is the receiver
    if message.receiver_id == current_user.id and not message.read_at:
        message.read_at = datetime.utcnow()
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error marking message as read: {str(e)}', 'error')
    
    # Get the related property if it exists
    related_property = Property.query.get(message.related_property_id) if message.related_property_id else None
    return render_template('message_detail.html', message=message, related_property=related_property)

@app.route('/messages/reply/<int:message_id>', methods=['GET', 'POST'])
@login_required
def reply_message(message_id):
    original_message = Message.query.get_or_404(message_id)
    if original_message.receiver_id != current_user.id and original_message.sender_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('message_list'))
    
    if request.method == 'POST':
        content = request.form.get('content')
        subject = f"Re: {original_message.subject}"
        
        # Set receiver to the original sender if current user was receiver, otherwise to original receiver
        receiver_id = original_message.sender_id if original_message.receiver_id == current_user.id else original_message.receiver_id
        
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            subject=subject,
            content=content,
            related_property_id=original_message.related_property_id
        )
        db.session.add(message)
        db.session.commit()
        
        flash('Reply sent successfully!', 'success')
        return redirect(url_for('message_list'))
    
    # For GET request, show the reply form
    users = User.query.filter(User.id != current_user.id).all()
    properties = Property.query.all()
    return render_template('message_form.html', 
                         users=users, 
                         properties=properties,
                         reply_to=original_message.sender_id,
                         subject=f"Re: {original_message.subject}",
                         original_message=original_message)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Update the report generation functions
def generate_property_report():
    # Create a PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    elements = []

    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph('Property Report', title_style))
    elements.append(Spacer(1, 12))

    # Prepare data for table
    properties = Property.query.all()
    table_data = [['Title', 'Location', 'Price', 'Status', 'Type', 'Agent']]
    
    # Collect data for visualizations
    property_types = []
    property_status = []
    prices = []
    locations = []

    for prop in properties:
        agent = User.query.get(prop.agent_id)
        table_data.append([
            prop.title,
            prop.location,
            f"₦{prop.price:,.2f}",
            prop.status,
            prop.property_type,
            agent.name if agent else 'Unknown'
        ])
        property_types.append(prop.property_type)
        property_status.append(prop.status)
        prices.append(prop.price)
        locations.append(prop.location)

    # Create property type distribution chart
    plt.figure(figsize=(8, 4))
    type_counts = Counter(property_types)
    plt.pie(type_counts.values(), labels=type_counts.keys(), autopct='%1.1f%%')
    plt.title('Property Type Distribution')
    type_chart = BytesIO()
    plt.savefig(type_chart, format='png', bbox_inches='tight')
    plt.close()

    # Create status distribution chart
    plt.figure(figsize=(8, 4))
    status_counts = Counter(property_status)
    plt.bar(status_counts.keys(), status_counts.values())
    plt.title('Property Status Distribution')
    plt.xticks(rotation=45)
    status_chart = BytesIO()
    plt.savefig(status_chart, format='png', bbox_inches='tight')
    plt.close()

    # Create price range chart
    plt.figure(figsize=(8, 4))
    plt.hist(prices, bins=10)
    plt.title('Property Price Distribution')
    plt.xlabel('Price (₦)')
    plt.ylabel('Number of Properties')
    price_chart = BytesIO()
    plt.savefig(price_chart, format='png', bbox_inches='tight')
    plt.close()

    # Add charts to the PDF
    elements.append(Paragraph('Property Analytics', styles['Heading2']))
    elements.append(Spacer(1, 12))
    
    # Add the charts in a row
    elements.append(Image(type_chart, width=250, height=150))
    elements.append(Spacer(1, 12))
    elements.append(Image(status_chart, width=250, height=150))
    elements.append(Spacer(1, 12))
    elements.append(Image(price_chart, width=250, height=150))
    elements.append(Spacer(1, 20))

    # Add the table
    elements.append(Paragraph('Property Details', styles['Heading2']))
    elements.append(Spacer(1, 12))
    
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(table)

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='property_report.pdf'
    )

def generate_booking_report():
    # Create a PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    elements = []

    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph('Booking Report', title_style))
    elements.append(Spacer(1, 12))

    # Prepare data for table
    bookings = Booking.query.all()
    table_data = [['Property', 'User', 'Booking Date', 'Status', 'Duration', 'Move In', 'Move Out']]
    
    # Collect data for visualizations
    booking_status = []
    booking_dates = []
    durations = []

    for booking in bookings:
        property = Property.query.get(booking.property_id)
        user = User.query.get(booking.user_id)
        table_data.append([
            property.title if property else 'Unknown',
            user.name if user else 'Unknown',
            booking.booking_date.strftime('%Y-%m-%d'),
            booking.status,
            f"{booking.duration_months} months" if booking.duration_months else 'N/A',
            booking.move_in_date.strftime('%Y-%m-%d') if booking.move_in_date else 'N/A',
            booking.move_out_date.strftime('%Y-%m-%d') if booking.move_out_date else 'N/A'
        ])
        booking_status.append(booking.status)
        booking_dates.append(booking.booking_date)
        if booking.duration_months:
            durations.append(booking.duration_months)

    # Create booking status chart
    plt.figure(figsize=(8, 4))
    status_counts = Counter(booking_status)
    plt.pie(status_counts.values(), labels=status_counts.keys(), autopct='%1.1f%%')
    plt.title('Booking Status Distribution')
    status_chart = BytesIO()
    plt.savefig(status_chart, format='png', bbox_inches='tight')
    plt.close()

    # Create booking timeline chart
    plt.figure(figsize=(8, 4))
    plt.hist(booking_dates, bins=20)
    plt.title('Booking Timeline')
    plt.xlabel('Date')
    plt.ylabel('Number of Bookings')
    plt.xticks(rotation=45)
    timeline_chart = BytesIO()
    plt.savefig(timeline_chart, format='png', bbox_inches='tight')
    plt.close()

    # Create duration distribution chart
    if durations:
        plt.figure(figsize=(8, 4))
        plt.hist(durations, bins=10)
        plt.title('Booking Duration Distribution')
        plt.xlabel('Duration (months)')
        plt.ylabel('Number of Bookings')
        duration_chart = BytesIO()
        plt.savefig(duration_chart, format='png', bbox_inches='tight')
        plt.close()

    # Add charts to the PDF
    elements.append(Paragraph('Booking Analytics', styles['Heading2']))
    elements.append(Spacer(1, 12))
    
    elements.append(Image(status_chart, width=250, height=150))
    elements.append(Spacer(1, 12))
    elements.append(Image(timeline_chart, width=250, height=150))
    elements.append(Spacer(1, 12))
    if durations:
        elements.append(Image(duration_chart, width=250, height=150))
        elements.append(Spacer(1, 20))

    # Add the table
    elements.append(Paragraph('Booking Details', styles['Heading2']))
    elements.append(Spacer(1, 12))
    
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(table)

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='booking_report.pdf'
    )

def generate_maintenance_report():
    # Create a PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    elements = []

    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph('Maintenance Report', title_style))
    elements.append(Spacer(1, 12))

    # Prepare data for table
    maintenance_tasks = Maintenance.query.all()
    table_data = [['Property', 'Issue', 'Reporter', 'Priority', 'Status', 'Estimated Cost', 'Reported Date', 'Completed Date']]
    
    # Collect data for visualizations
    task_status = []
    priorities = []
    costs = []
    completion_times = []

    for task in maintenance_tasks:
        property = Property.query.get(task.property_id)
        reporter = User.query.get(task.reported_by)
        table_data.append([
            property.title if property else 'Unknown',
            task.title,
            reporter.name if reporter else 'Unknown',
            task.priority,
            task.status,
            f"₦{task.estimated_cost:,.2f}" if task.estimated_cost else '₦0.00',
            task.created_at.strftime('%Y-%m-%d'),
            task.completed_at.strftime('%Y-%m-%d') if task.completed_at else 'Not completed'
        ])
        task_status.append(task.status)
        priorities.append(task.priority)
        if task.estimated_cost:
            costs.append(task.estimated_cost)
        if task.completed_at:
            completion_time = (task.completed_at - task.created_at).days
            completion_times.append(completion_time)

    # Create status distribution chart
    plt.figure(figsize=(8, 4))
    status_counts = Counter(task_status)
    plt.pie(status_counts.values(), labels=status_counts.keys(), autopct='%1.1f%%')
    plt.title('Maintenance Task Status Distribution')
    status_chart = BytesIO()
    plt.savefig(status_chart, format='png', bbox_inches='tight')
    plt.close()

    # Create priority distribution chart
    plt.figure(figsize=(8, 4))
    priority_counts = Counter(priorities)
    plt.bar(priority_counts.keys(), priority_counts.values())
    plt.title('Task Priority Distribution')
    plt.xlabel('Priority')
    plt.ylabel('Number of Tasks')
    priority_chart = BytesIO()
    plt.savefig(priority_chart, format='png', bbox_inches='tight')
    plt.close()

    # Create cost distribution chart
    if costs:
        plt.figure(figsize=(8, 4))
        plt.hist(costs, bins=10)
        plt.title('Maintenance Cost Distribution')
        plt.xlabel('Cost (₦)')
        plt.ylabel('Number of Tasks')
        cost_chart = BytesIO()
        plt.savefig(cost_chart, format='png', bbox_inches='tight')
        plt.close()

    # Add charts to the PDF
    elements.append(Paragraph('Maintenance Analytics', styles['Heading2']))
    elements.append(Spacer(1, 12))
    
    elements.append(Image(status_chart, width=250, height=150))
    elements.append(Spacer(1, 12))
    elements.append(Image(priority_chart, width=250, height=150))
    elements.append(Spacer(1, 12))
    if costs:
        elements.append(Image(cost_chart, width=250, height=150))
        elements.append(Spacer(1, 20))

    # Add the table
    elements.append(Paragraph('Maintenance Details', styles['Heading2']))
    elements.append(Spacer(1, 12))
    
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(table)

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='maintenance_report.pdf'
    )

# Add a route for viewing all properties in card view
@app.route('/properties')
def view_properties():
    properties = Property.query.order_by(Property.created_at.desc()).all()
    return render_template('property_list.html', properties=properties)

# Add a route to get available agents for a property type
@app.route('/agents/available', methods=['GET'])
@admin_required
def get_available_agents():
    property_type = request.args.get('property_type', 'rent')
    agents = User.query.filter(User.role == ROLE_AGENT).all()
    return jsonify([{'id': agent.id, 'name': agent.name} for agent in agents])

# Helper function to send notifications
def send_maintenance_notification(maintenance, notification_type):
    # Get admin users
    admin_users = User.query.filter_by(role=ROLE_ADMIN).all()
    property = maintenance.property
    reporter = User.query.get(maintenance.reported_by)
    
    # Find current tenant
    current_tenant = None
    active_booking = Booking.query.filter_by(
        property_id=property.id,
        status='paid'
    ).order_by(Booking.created_at.desc()).first()
    if active_booking:
        current_tenant = User.query.get(active_booking.user_id)
    
    # Prepare notification content based on type
    if notification_type == 'new':
        subject = f"New Maintenance Request - {property.title}"
        content = f"A new maintenance request has been submitted for {property.title}.\n\n" \
                f"Issue: {maintenance.title}\n" \
                f"Priority: {maintenance.priority}\n" \
                f"Reported by: {reporter.name}\n" \
                f"Description: {maintenance.description}"
    elif notification_type == 'status_update':
        subject = f"Maintenance Status Updated - {property.title}"
        content = f"The maintenance request for {property.title} has been updated to {maintenance.status}.\n\n" \
                f"Issue: {maintenance.title}\n" \
                f"Updated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

    # Send to property agent
    agent_notification = Message(
        sender_id=maintenance.reported_by,
        receiver_id=property.agent_id,
        subject=subject,
        content=content,
        related_property_id=property.id
    )
    db.session.add(agent_notification)

    # Send to all admins
    for admin in admin_users:
        admin_notification = Message(
            sender_id=maintenance.reported_by,
            receiver_id=admin.id,
            subject=subject,
            content=content,
            related_property_id=property.id
        )
        db.session.add(admin_notification)
    
    # Send to tenant if they exist and they're not the reporter
    if current_tenant and current_tenant.id != maintenance.reported_by:
        tenant_notification = Message(
            sender_id=maintenance.reported_by,
            receiver_id=current_tenant.id,
            subject=subject,
            content=content,
            related_property_id=property.id
        )
        db.session.add(tenant_notification)

def send_property_status_notification(property, old_status, new_status):
    # Get admin users
    admin_users = User.query.filter_by(role=ROLE_ADMIN).all()
    agent = User.query.get(property.agent_id)
    
    subject = f"Property Status Changed - {property.title}"
    content = f"The status of property {property.title} has been changed from {old_status} to {new_status}.\n\n" \
            f"Location: {property.location}\n" \
            f"Price: ₦{property.price:,.2f}\n" \
            f"Type: {property.property_type}\n" \
            f"Agent: {agent.name}"

    # Send to all admins
    for admin in admin_users:
        notification = Message(
            sender_id=property.agent_id,
            receiver_id=admin.id,
            subject=subject,
            content=content,
            related_property_id=property.id
        )
        db.session.add(notification)

    # If status change is by admin, notify agent
    if current_user.role == ROLE_ADMIN:
        agent_notification = Message(
            sender_id=current_user.id,
            receiver_id=property.agent_id,
            subject=subject,
            content=content,
            related_property_id=property.id
        )
        db.session.add(agent_notification)

# Update property status changes to include notifications
@app.route('/property/<int:property_id>/status', methods=['POST'])
@login_required
def update_property_status(property_id):
    property = Property.query.get_or_404(property_id)
    if current_user.role != ROLE_ADMIN and (current_user.role != ROLE_AGENT or property.agent_id != current_user.id):
        flash('Unauthorized access.')
        return redirect(url_for('index'))
    
    old_status = property.status
    new_status = request.form.get('status')
    if new_status in ['available', 'pending', 'rented', 'sold']:
        property.status = new_status
        try:
            db.session.commit()
            # Send notification about status change
            send_property_status_notification(property, old_status, new_status)
            db.session.commit()
            flash('Property status updated successfully!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating property status: {str(e)}', 'error')
    else:
        flash('Invalid status provided.')
    
    return redirect(url_for('property_detail', property_id=property_id))

def init_db():
    """Initialize the database if it doesn't exist"""
    try:
        with app.app_context():
            inspector = inspect(db.engine)
            
            # Create tables if they don't exist
            if not inspector.has_table('maintenance'):
                Maintenance.__table__.create(db.engine)
            
            # Add maintenance status column if it doesn't exist
            if inspector.has_table('maintenance'):
                columns = [c['name'] for c in inspector.get_columns('maintenance')]
                if 'status' not in columns:
                    db.engine.execute('ALTER TABLE maintenance ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT ?', 
                                    (MAINTENANCE_STATUS_PENDING,))
            
            # Create all tables
            db.create_all()
            
            # Check if admin user exists
            admin = User.query.filter_by(email='admin@example.com').first()
            if not admin:
                admin = User(
                    email='admin@example.com',
                    name='Admin User',
                    role=ROLE_ADMIN,
                    password_hash=generate_password_hash('admin123')
                )
                db.session.add(admin)
                db.session.commit()
        return True
    except Exception as e:
        return False

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True) 