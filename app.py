# aqualedger-backend/app.py
from flask import Flask, jsonify
from flask_cors import CORS 
import os
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from flask_migrate import Migrate

app = Flask(__name__)

#auth code and db code
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aqualedger.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-jwt-key'  # CHANGE THIS in production!
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Add this line
jwt = JWTManager(app)

#Models start here
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    mpesa_code = db.Column(db.String(13))
    
    def set_password(self, password):
        """Hash and store the password."""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)

#Catch model
class Catch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # reference to User
    species = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    buyer = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    mpesa_code = db.Column(db.String(15))

    # Relationship (optional, to easily access user from catch if needed)
    user = db.relationship('User', backref=db.backref('catches', lazy=True))


#models end here

CORS(app) # Enables CORS for all routes by default:contentReference[oaicite:3]{index=3}
#routes start here
@app.route("/")
def index():
    return jsonify({"message": "Welcome to Aqua Ledger API"})


# Register route
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}  # get JSON from request body
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    # Basic validation
    if not (name and email and password):
        return {"message": "Name, email, and password are required."}, 400
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return {"message": "User with this email already exists."}, 409
    # Create new user
    new_user = User(name=name, email=email)
    new_user.set_password(password)  # hash the password
    db.session.add(new_user)
    db.session.commit()
    access_token = create_access_token(identity=str(new_user.id)) # use user.id as identity
    return {"message": f"User {name} registered successfully."}, 201

# Login route
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    # Basic validation
    if not (email and password):
        return {"msg": "Email and password required"}, 400
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        # Credentials are correct – create a JWT
        access_token = create_access_token(identity=str(user.id)) # use user.id as identity
        return {"token": access_token, "user": {"name": user.name, "email": user.email}}
    else:
        return {"msg": "Invalid email or password"}, 401

#add catch route
@app.route("/catches", methods=["POST"])
@jwt_required()  # user must be logged in (token required)
def add_catch():
    user_id = int(get_jwt_identity())  # this is the identity we set in the token (user.id)
    data = request.get_json() or {}
    species = data.get('species')
    quantity = data.get('quantity')
    price = data.get('price')
    buyer = data.get('buyer')
    mpesa = data.get('mpesa_code')
    if not (species and quantity and price and buyer):
        return {"msg": "All fields (species, quantity, price, buyer) are required."}, 400
    # Create catch record
    new_catch = Catch(user_id=user_id, species=species, quantity=quantity, price=price, buyer=buyer, mpesa_code=mpesa)
    db.session.add(new_catch)
    db.session.commit()
    # Return the created catch data
    return {
        "id": new_catch.id,
        "species": new_catch.species,
        "quantity": new_catch.quantity,
        "price": new_catch.price,
        "buyer": new_catch.buyer,
        "date": new_catch.date.isoformat()
    }, 201

#get catch route
@app.route("/catches", methods=["GET"])
@jwt_required()
def get_catches():
    user_id = int(get_jwt_identity()) # Get the user ID from the JWT token
    # Query catches for this user, most recent first
    catches = Catch.query.filter_by(user_id=user_id).order_by(Catch.date.desc()).all()
    # Convert to list of dicts for JSON output
    result = []
    for c in catches:
        result.append({
            "id": c.id,
            "species": c.species,
            "quantity": c.quantity,
            "price": c.price,
            "buyer": c.buyer,
            "date": c.date.isoformat(),
            "mpesa_code": c.mpesa_code
        })
    return {"catches": result}

#update catch route
@app.route("/catches/<int:catch_id>", methods=["PUT"])
@jwt_required()
def update_catch(catch_id):
    user_id = int(get_jwt_identity())
    catch = Catch.query.filter_by(id=catch_id, user_id=user_id).first()
    if not catch:
        return {"msg": "Catch not found or not authorized"}, 404
    data = request.get_json() or {}
    # Update allowed fields if provided
    catch.species = data.get('species', catch.species)
    catch.quantity = data.get('quantity', catch.quantity)
    catch.price = data.get('price', catch.price)
    catch.buyer = data.get('buyer', catch.buyer)
    # Note: We won't allow changing the date for simplicity
    db.session.commit()
    return {"msg": "Catch updated successfully."}

#delete catch route
@app.route("/catches/<int:catch_id>", methods=["DELETE"])
@jwt_required()
def delete_catch(catch_id):
    user_id = int(get_jwt_identity())
    catch = Catch.query.filter_by(id=catch_id, user_id=user_id).first()
    if not catch:
        return {"msg": "Catch not found or not authorized"}, 404
    db.session.delete(catch)
    db.session.commit()
    return {"msg": "Catch deleted."}

#summary route
@app.route("/summary")
@jwt_required()
def get_summary():
    user_id = get_jwt_identity()
    today = datetime.utcnow().date()
    week_start = today - timedelta(days=today.weekday())  # Monday of current week
    # Query for today
    today_catches = Catch.query.filter(
        db.func.date(Catch.date) == today,
        Catch.user_id == user_id
    ).all()
    # Query for this week
    week_catches = Catch.query.filter(
        Catch.date >= week_start,
        Catch.user_id == user_id
    ).all()
    total_today_qty = sum(c.quantity for c in today_catches)
    total_today_earnings = sum(c.price for c in today_catches)
    total_week_qty = sum(c.quantity for c in week_catches)
    total_week_earnings = sum(c.price for c in week_catches)
    return {
        "today_qty": total_today_qty, "today_earnings": total_today_earnings,
        "week_qty": total_week_qty, "week_earnings": total_week_earnings
    }


#routes end here


# Create the database and tables
with app.app_context():
    db.create_all()
    
if __name__ == "__main__":
    app.run(debug=True)
