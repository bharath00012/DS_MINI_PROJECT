import os
import pandas as pd
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from io import StringIO

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')  # Fallback if .env is missing
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@127.0.0.1/inventory_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with app
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    inventories = db.relationship('Inventory', backref='owner', lazy=True)

# Define Inventory model
class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    data = db.Column(db.Text, nullable=False)  # Store CSV content as text
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize the database
def init_db():
    with app.app_context():
        db.create_all()

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Create new user
        new_user = User(
            username=username,
            password=generate_password_hash(password, method='sha256')
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials.')
            return redirect(url_for('login'))

        # Log the user in
        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    inventories = Inventory.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', inventories=inventories)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file part.')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file.')
        return redirect(url_for('dashboard'))

    if file and file.filename.endswith('.csv'):
        filename = file.filename
        data = file.read().decode('utf-8')

        # Save to database
        new_inventory = Inventory(filename=filename, data=data, user_id=current_user.id)  # Ensure user_id is set correctly
        db.session.add(new_inventory)
        db.session.commit()

        flash('File uploaded successfully.')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid file type. Please upload a CSV file.')
        return redirect(url_for('dashboard'))

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    query = request.json.get('query', '').lower()
    inventory_id = request.json.get('inventory_id')

    # Fetch inventory
    inventory = Inventory.query.filter_by(id=inventory_id, user_id=current_user.id).first()
    if not inventory:
        return jsonify({'error': 'Inventory not found.'}), 404

    # Read CSV data using pandas
    df = pd.read_csv(StringIO(inventory.data))

    response = ""

    # Handle different types of queries
    if 'product count' in query:
        if 'product' in df.columns and 'count' in df.columns:
            total = df['count'].sum()
            response = f'Total product count: {total}'
        else:
            response = 'CSV must contain "product" and "count" columns.'

    elif 'good selling' in query or 'good selling product' in query:
        if 'product' in df.columns and 'sales' in df.columns:
            top_product = df.groupby('product')['sales'].sum().idxmax()
            response = f'Good selling product: {top_product}'
        else:
            response = 'CSV must contain "product" and "sales" columns.'

    elif 'threshold' in query or 'low stock' in query:
        if 'product' in df.columns and 'count' in df.columns:
            low_stock = df[df['count'] < 50]['product'].tolist()  # Change 50 to your threshold variable if needed
            if low_stock:
                response = f'Products below threshold: {", ".join(low_stock)}'
            else:
                response = 'No products are below the threshold.'
        else:
            response = 'CSV must contain "product" and "count" columns.'

    elif 'count of' in query:  # New feature to get specific product count
        product_name = query.split('count of ')[-1].strip()  # Extract product name from query
        if 'product' in df.columns and 'count' in df.columns:
            product_row = df[df['product'].str.lower() == product_name.lower()]
            if not product_row.empty:
                product_count = product_row['count'].values[0]
                response = f'The count of "{product_name}" is: {product_count}'
            else:
                response = f'Product "{product_name}" not found in inventory.'
        else:
            response = 'CSV must contain "product" and "count" columns.'

    else:
        response = "I'm sorry, I didn't understand that. You can ask about 'product count', 'good selling products', 'low stock products', or 'count of [product name]'."

    return jsonify({'response': response})

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)
