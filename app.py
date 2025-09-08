# aqualedger-backend/app.py
import os
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_migrate import Migrate
from sqlalchemy import func
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)

# --- Config ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aqualedger.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-jwt-key'  # set a fixed value in Render env
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # tokens last a day

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app)  # allow frontend to call this API

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # wide enough for new hash formats
    # NOTE: mpesa_code does NOT belong to the user; keep only on Catch.
    # If you already added it by mistake, you can leave it or remove via migration.

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Catch(db.Model):
    # ⚠️ FIX: do NOT put any runtime code on this line (you had "user_id = int(get_jwt_identity())" here)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    species = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Float, nullable=False)  # float so you can log 12.5 kg
    price = db.Column(db.Float, nullable=False)     # price per kg
    buyer = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    mpesa_code = db.Column(db.String(15))           # optional

    user = db.relationship('User', backref=db.backref('catches', lazy=True))

class SecureModelView(ModelView):
    def is_accessible(self):
        token = request.headers.get('X-Admin-Token') or request.args.get('admin_token')
        return token and token == os.getenv('ADMIN_TOKEN')
    def inaccessible_callback(self, name, **kwargs):
        return abort(403)

admin = Admin(app, name="Aqua Ledger Admin", template_mode="bootstrap4", url="/admin")
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Catch, db.session))

# --- Routes ---
@app.route("/")
def index():
    return jsonify({"message": "Welcome to Aqua Ledger API"})

# Register → return a token so the user is logged in right away
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    if not (name and email and password):
        return {"message": "Name, email, and password are required."}, 400
    if User.query.filter_by(email=email).first():
        return {"message": "User with this email already exists."}, 409

    new_user = User(name=name, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=str(new_user.id))
    return {
        "message": f"User {name} registered successfully.",
        "token": access_token,
        "user": {"name": new_user.name, "email": new_user.email}
    }, 201

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get('email'); password = data.get('password')
    if not (email and password):
        return {"msg": "Email and password required"}, 400
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user.id))
        return {"token": access_token, "user": {"name": user.name, "email": user.email}}
    return {"msg": "Invalid email or password"}, 401

# Create Catch
@app.route("/catches", methods=["POST"])
@jwt_required()
def add_catch():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    species = data.get('species')
    quantity = data.get('quantity')
    price = data.get('price')
    buyer = data.get('buyer')
    mpesa = data.get('mpesa_code')
    # allow zero but not None
    if not (species and quantity is not None and price is not None and buyer):
        return {"msg": "All fields (species, quantity, price, buyer) are required."}, 400

    new_catch = Catch(
        user_id=user_id, species=species,
        quantity=float(quantity), price=float(price),
        buyer=buyer, mpesa_code=mpesa
    )
    db.session.add(new_catch)
    db.session.commit()
    return {
        "id": new_catch.id,
        "species": new_catch.species,
        "quantity": new_catch.quantity,
        "price": new_catch.price,
        "buyer": new_catch.buyer,
        "date": new_catch.date.isoformat(),
        "mpesa_code": new_catch.mpesa_code
    }, 201

# List Catches
@app.route("/catches", methods=["GET"])
@jwt_required()
def get_catches():
    user_id = int(get_jwt_identity())
    catches = Catch.query.filter_by(user_id=user_id).order_by(Catch.date.desc()).all()
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

# Update Catch
@app.route("/catches/<int:catch_id>", methods=["PUT"])
@jwt_required()
def update_catch(catch_id):
    user_id = int(get_jwt_identity())
    catch = Catch.query.filter_by(id=catch_id, user_id=user_id).first()
    if not catch:
        return {"msg": "Catch not found or not authorized"}, 404
    data = request.get_json() or {}
    catch.species = data.get('species', catch.species)
    catch.quantity = data.get('quantity', catch.quantity)
    catch.price = data.get('price', catch.price)
    catch.buyer = data.get('buyer', catch.buyer)
    catch.mpesa_code = data.get('mpesa_code', catch.mpesa_code)
    db.session.commit()
    return {"msg": "Catch updated successfully."}

# Delete Catch
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

# Summary
@app.route("/summary")
@jwt_required()
def get_summary():
    user_id = int(get_jwt_identity())
    today = datetime.utcnow().date()
    week_start = today - timedelta(days=today.weekday())  # Monday
    today_catches = Catch.query.filter(
        func.date(Catch.date) == today,
        Catch.user_id == user_id
    ).all()
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

# Create tables (no-op if they exist)
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)

