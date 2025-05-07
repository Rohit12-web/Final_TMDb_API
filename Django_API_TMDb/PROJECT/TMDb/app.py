from flask import Flask, render_template, redirect, request, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "app.db")

app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "Your secret key"

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Review(db.Model):
    __tablename__ = "review"

    id = db.Column(db.Integer, primary_key=True)
    movie_name = db.Column(db.String(100), nullable=False)
    review = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def create_admin_user():
    admin_email = "sim@gmail.com"
    admin_password = "12345"
    
    try:
        admin_user = User.query.filter_by(email=admin_email).first()
        if not admin_user:
            admin_user = User(
                name="Admin",
                email=admin_email,
                is_admin=True
            )
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully")
        else:
            print("Admin user already exists")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating admin user: {str(e)}")

with app.app_context():
    print("Creating database tables...")
    db.create_all()
    print("Database tables created successfully")
    create_admin_user()
@app.route("/")
def home():
    name = session.get("name")
    reviews = Review.query.order_by(Review.created_at.desc()).all()
    return render_template("home.html", name=name, reviews=reviews)

@app.route('/submit_review', methods=['POST'])
@login_required
def submit_review():
    movie_name = request.form.get('movie_name')
    review_text = request.form.get('review')
    rating = request.form.get('rating')
    
    if not all([movie_name, review_text, rating]):
        flash("Please fill in all fields", "error")
        return redirect(url_for('rate_movie'))
    
    try:
        rating = int(rating)
        if not 1 <= rating <= 5:
            raise ValueError
        
        new_review = Review(
            movie_name=movie_name,
            review=review_text,
            rating=rating,
            user_id=current_user.id
        )
        
        print("Adding review to database")  
        db.session.add(new_review)
        db.session.commit()
        print("Review successfully added to database")  

        flash("Review submitted successfully!", "success")
        return redirect(url_for('rate_movie'))

    except ValueError:
        flash("Rating must be between 1 and 5", "error")
        return redirect(url_for('rate_movie'))

    except Exception as e:
        print(f"Error submitting review: {str(e)}")  
        db.session.rollback()
        flash("Error submitting review", "error")
        return redirect(url_for('rate_movie'))



@app.route("/Stree 2")
def card2():
    return render_template("card2.html")

@app.route("/about us")
def about():
    return render_template("user.html")

@app.route("/Watchlist")
def main():
    return render_template("main.html")

@app.route("/Movie Recommendations")
def rating():
    return render_template("recomend.html")

@app.route("/dashboard")
@login_required
def dashboard():
    name = session.get("name")
    email = session.get("email")
    return render_template("dashboard.html", name=name, email=email)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            session["email"] = user.email
            session["name"] = user.name
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid email or password!", "danger")

    return render_template("Login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        new_user = User(name=name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("name", None)
    session.pop("email", None)
    flash("Logged out successfully!", "info")
    return redirect(url_for("home"))

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    mobile_no = db.Column(db.String(15), nullable=False)  

    message = db.Column(db.Text, nullable=False)

    def _repr_(self):
        return f'<Contact {self.name}>'


with app.app_context():
    db.create_all()


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        mobile_no = request.form['mobile_no']
        message = request.form['message']

        
        new_contact = Contact(name=name, email=email, mobile_no=mobile_no, message=message)
        db.session.add(new_contact)
        db.session.commit()


    return render_template('contact.html')




class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rate = db.Column(db.String(10), nullable=False)

    def _repr_(self):
        return f'<Rating {self.rate}>'

with app.app_context():
    db.create_all()


@app.route('/Jatt & Juliet 3', methods=['GET', 'POST'])
def rate_movie():
    if request.method == 'POST':
        rate = request.form['rate']
        
        
        new_rating = Rating(rate=rate)
        db.session.add(new_rating)
        db.session.commit()
        
        session["rate"] = rate 

        

        return redirect(url_for('rate_movie')) 

    return render_template('card1.html', rate=session.get("rate"))
if __name__ == "__main__":
    app.run(debug=True)

    """
Flask Backend Enhancements

This file contains suggestions for enhancing your Flask backend to better support the Django frontend.
"""

# Add these to your Flask app to improve the API

# 1. Add a health check endpoint to verify API availability
@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'ok',
        'message': 'Flask API is operational'
    }), 200

# 2. Improve error handling for the get_contact endpoint
@app.route('/api/contacts/<int:contact_id>', methods=['GET'])
def get_contact(contact_id):
    """Get a single contact by ID"""
    contact = Contact.query.get(contact_id)
    
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    return jsonify({
        'id': contact.id,
        'name': contact.name,
        'email': contact.email,
        'mobile_no': contact.mobile_no,
        'message': contact.message
    }), 200

# 3. Improve error handling for delete_contact endpoint
@app.route('/api/contacts/<int:contact_id>', methods=['DELETE'])
def delete_contact(contact_id):
    """Delete a contact by ID"""
    contact = Contact.query.get(contact_id)
    
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    db.session.delete(contact)
    db.session.commit()
    
    return jsonify({
        'message': 'Contact deleted successfully',
        'id': contact_id
    }), 200

# 4. Add CORS support to allow Django to access the API
# First, install flask-cors: pip install flask-cors
# Then add to your Flask app:

from flask_cors import CORS

# Apply CORS to your Flask app
CORS(app, resources={r"/api/*": {"origins": "http://localhost:8000"}})

# 5. Add pagination support for larger datasets
@app.route('/api/contacts/page/<int:page>', methods=['GET'])
def get_contacts_paginated(page):
    """Get contacts with pagination"""
    per_page = request.args.get('per_page', 10, type=int)
    contacts_pagination = Contact.query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'contacts': [{
            'id': contact.id,
            'name': contact.name,
            'email': contact.email,
            'mobile_no': contact.mobile_no,
            'message': contact.message
        } for contact in contacts_pagination.items],
        'pagination': {
            'total': contacts_pagination.total,
            'pages': contacts_pagination.pages,
            'current_page': contacts_pagination.page,
            'per_page': per_page,
            'has_next': contacts_pagination.has_next,
            'has_prev': contacts_pagination.has_prev
        }
    }), 200