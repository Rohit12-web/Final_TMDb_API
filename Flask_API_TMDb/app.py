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

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    mobile_no = db.Column(db.String(15), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Contact {self.name}>'

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rate = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f'<Rating {self.rate}>'

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
    admin_email = "Admin@gmail.com"
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

@app.route("/Movie Recommendati 
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
            # Check if the request is from an API client (e.g., Postman)
            if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                return jsonify({
                    "message": "Login successful",
                    "user": {
                        "id": user.id,
                        "name": user.name,
                        "email": user.email,
                        "is_admin": user.is_admin
                    }
                }), 200
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            # Check if the request is from an API client
            if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                return jsonify({"error": "Invalid email or password"}), 401
            flash("Invalid email or password!", "danger")

    # For GET requests, return the login page for web users
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

# API Routes
@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'is_admin': user.is_admin
    } for user in users]), 200

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'is_admin': user.is_admin
    }), 200

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json()
    if not data or not all(key in data for key in ['name', 'email', 'password']):
        return jsonify({'error': 'Name, email, and password are required'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    user = User(name=data['name'], email=data['email'], is_admin=data.get('is_admin', False))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'is_admin': user.is_admin
    }), 201

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    user.name = data.get('name', user.name)
    if 'email' in data:
        if User.query.filter_by(email=data['email']).first() and data['email'] != user.email:
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    if 'password' in data:
        user.set_password(data['password'])
    user.is_admin = data.get('is_admin', user.is_admin) if current_user.is_admin else user.is_admin
    db.session.commit()
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'is_admin': user.is_admin
    }), 200

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'}), 200

@app.route('/api/reviews', methods=['GET'])
def get_reviews():
    reviews = Review.query.all()
    return jsonify([{
        'id': review.id,
        'movie_name': review.movie_name,
        'review': review.review,
        
        'created_at': review.created_at.isoformat(),
        'user_id': review.user_id
    } for review in reviews]), 200

@app.route('/api/reviews/<int:review_id>', methods=['GET'])
def get_review(review_id):
    review = Review.query.get_or_404(review_id)
    return jsonify({
        'id': review.id,
        'movie_name': review.movie_name,
        'review': review.review,
       
        'created_at': review.created_at.isoformat(),
        'user_id': review.user_id
    }), 200

@app.route('/api/reviews', methods=['POST'])
@login_required
def create_review():
    data = request.get_json()
    if not data or not all(key in data for key in ['movie_name', 'review', ]):
        return jsonify({'error': 'Movie name, review,are required'}), 400
    try:
        rating = int(data['rating'])
        if not 1 <= rating <= 5:
            return jsonify({'error': 'Rating must be between 1 and 5'}), 400
    except ValueError:
        return jsonify({'error': 'Rating must be an integer'}), 400
    review = Review(
        movie_name=data['movie_name'],
        review=data['review'],
        
        user_id=current_user.id
    )
    db.session.add(review)
    db.session.commit()
    return jsonify({
        'id': review.id,
        'movie_name': review.movie_name,
        'review': review.review,
        
        'created_at': review.created_at.isoformat(),
        'user_id': review.user_id
    }), 201

@app.route('/api/reviews/<int:review_id>', methods=['PUT'])
@login_required
def update_review(review_id):
    review = Review.query.get_or_404(review_id)
    if review.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    review.movie_name = data.get('movie_name', review.movie_name)
    review.review = data.get('review', review.review)
   
    db.session.commit()
    return jsonify({
        'id': review.id,
        'movie_name': review.movie_name,
        'review': review.review,
        
        'created_at': review.created_at.isoformat(),
        'user_id': review.user_id
    }), 200

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
@login_required
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    if review.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(review)
    db.session.commit()
    return jsonify({'message': 'Review deleted'}), 200


@app.route('/api/contacts', methods=['GET'])
def get_contacts():
    contacts = Contact.query.all()
    return jsonify([{
        'id': contact.id,
        'name': contact.name,
        'email': contact.email,
        'mobile_no': contact.mobile_no,
        'message': contact.message
    } for contact in contacts]), 200

@app.route('/api/contacts/<int:contact_id>', methods=['GET'])
def get_contact(contact_id):
    contact = Contact.query.get(contact_id)
    if contact is None:
        return jsonify({"error": "Contact not found"}), 404
    try:
        return jsonify({
            "id": contact.id,
            "name": contact.name,
            "email": contact.email,
            "mobile_no": contact.mobile_no,
            "message": contact.message
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/contacts', methods=['POST'])
def create_contact():
    data = request.get_json()
    if not data or not all(key in data for key in ['name', 'email', 'mobile_no', 'message']):
        return jsonify({'error': 'Name, email, mobile number, and message are required'}), 400
    
    new_contact = Contact(
        name=data['name'],
        email=data['email'],
        mobile_no=data['mobile_no'],
        message=data['message']
    )
    db.session.add(new_contact)
    db.session.commit()
    
    return jsonify({
        'id': new_contact.id,
        'name': new_contact.name,
        'email': new_contact.email,
        'mobile_no': new_contact.mobile_no,
        'message': new_contact.message
    }), 201

@app.route('/api/contacts/<int:contact_id>', methods=['DELETE'])
def delete_contact(contact_id):
    contact = Contact.query.get(contact_id)
    if contact is None:
        return jsonify({'error': f'Contact with ID {contact_id} not found'}), 404

    try:
        db.session.delete(contact)
        db.session.commit()
        return jsonify({"message": f"Contact with ID {contact_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f"An error occurred while deleting the contact: {str(e)}"}), 500


@app.route('/api/ratings', methods=['GET'])
def get_ratings():
    ratings = Rating.query.all()
    return jsonify([{
        'id': rating.id,
        'rate': rating.rate
    } for rating in ratings]), 200

@app.route('/api/ratings/<int:rating_id>', methods=['GET'])
def get_rating(rating_id):
    rating = Rating.query.get_or_404(rating_id)
    return jsonify({
        'id': rating.id,
        'rate': rating.rate
    }), 200

@app.route('/api/ratings', methods=['POST'])
def create_rating():
    data = request.get_json()
    if not data or 'rate' not in data:
        return jsonify({'error': 'Rate is required'}), 400
    rating = Rating(rate=data['rate'])
    db.session.add(rating)
    db.session.commit()
    return jsonify({
        'id': rating.id,
        'rate': rating.rate
    }), 201

@app.route('/api/ratings/<int:rating_id>', methods=['DELETE'])
@admin_required
def delete_rating(rating_id):
    rating = Rating.query.get_or_404(rating_id)
    db.session.delete(rating)
    db.session.commit()
    return jsonify({'message': 'Rating deleted'}), 200

if __name__ == "__main__":
    app.run(debug=True)