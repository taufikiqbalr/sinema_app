from flask import Flask, render_template, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from geoalchemy2 import Geometry
from geoalchemy2.shape import from_shape, to_shape
from shapely.geometry import shape
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

app = Flask(__name__)

# ─── Config ────────────────────────────────────────────────────────────────────
app.config['SQLALCHEMY_DATABASE_URI']       = 'postgresql://postgres:root@localhost/mymapdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY']                = 'rahasianegara'

db  = SQLAlchemy(app)
jwt = JWTManager(app)

# ─── JWT Error Handlers ────────────────────────────────────────────────────────
@jwt.unauthorized_loader
def unauthorized_callback(error):
    print("❌ JWT missing or invalid:", error)
    return jsonify({"msg": error}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    print("❌ Invalid JWT:", error)
    return jsonify({"msg": error}), 422

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print("⌛️ Expired JWT:", jwt_payload)
    return jsonify({"msg": "Token has expired"}), 401

# ─── Models ────────────────────────────────────────────────────────────────────
class Annotation(db.Model):
    __tablename__ = 'annotations'
    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    geom = db.Column(Geometry('POLYGON', srid=4326), nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

# ─── Conditional table creation ────────────────────────────────────────────────
with app.app_context():
    inspector = inspect(db.engine)
    for model in (Annotation, User):
        tbl = model.__tablename__
        if not inspector.has_table(tbl):
            model.__table__.create(db.engine)
            print(f"🛠 Created missing table '{tbl}'")

# ─── Page Routes ───────────────────────────────────────────────────────────────
@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/map')
def map_page():
    return render_template('map.html')

@app.route('/users_manage')
def users_page():
    return render_template('users.html')

# ─── Auth / User APIs ──────────────────────────────────────────────────────────
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data = request.get_json() or {}
    print("🔐 Register attempt:", data)
    if not data.get('username') or not data.get('password'):
        abort(400, "Username & password required")
    if User.query.filter_by(username=data['username']).first():
        abort(409, "Username already exists")
    u = User(username=data['username'])
    u.set_password(data['password'])
    db.session.add(u)
    db.session.commit()
    print(f"✅ Registered new user id={u.id}, username={u.username}")
    return jsonify({'id':u.id,'username':u.username}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    print("🔑 Login attempt:", data)
    if not data.get('username') or not data.get('password'):
        abort(400, "Username & password required")
    u = User.query.filter_by(username=data['username']).first()
    if not u or not u.check_password(data['password']):
        abort(401, "Bad credentials")
    token = create_access_token(identity=str(u.id))
    print(f"✅ Login success for user id={u.id}")
    return jsonify({'access_token': token})

@app.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    identity = get_jwt_identity()
    print(f"👥 list_users called by user_id={identity}")
    users = [{'id':u.id,'username':u.username} for u in User.query.all()]
    print(f"→ returning {len(users)} users")
    return jsonify(users)

@app.route('/users/<int:uid>', methods=['DELETE'])
@jwt_required()
def delete_user(uid):
    identity = get_jwt_identity()
    print(f"🗑 delete_user {uid} called by user_id={identity}")
    u = User.query.get_or_404(uid)
    db.session.delete(u); db.session.commit()
    return jsonify({'status':'deleted'})

# ─── Annotation CRUD APIs ──────────────────────────────────────────────────────
@app.route('/annotations', methods=['GET'])
@jwt_required()
def list_annotations():
    identity = get_jwt_identity()
    print(f"📄 list_annotations called by user_id={identity}")
    feats = []
    for a in Annotation.query.all():
        feats.append({
            'type': 'Feature',
            'id': a.id,
            'properties': {'name': a.name},
            'geometry': to_shape(a.geom).__geo_interface__
        })
    print(f"→ returning {len(feats)} annotations")
    return jsonify({'type':'FeatureCollection','features':feats})

@app.route('/save', methods=['POST'])
@jwt_required()
def save_annotation():
    identity = get_jwt_identity()
    data = request.get_json() or {}
    print(f"✏️ save_annotation called by user_id={identity} with data:", data)
    gj = data.get('geojson',{}).get('geometry')
    if not gj or gj.get('type')!='Polygon':
        abort(400, "Invalid GeoJSON Polygon")
    poly = shape(gj)
    geom = from_shape(poly, srid=4326)
    ann = Annotation(name=data.get('name','Unnamed'), geom=geom)
    db.session.add(ann); db.session.commit()
    print(f"✅ Saved annotation id={ann.id}")
    return jsonify({'status':'ok','id':ann.id})

@app.route('/annotations/<int:aid>', methods=['PUT'])
@jwt_required()
def update_annotation(aid):
    identity = get_jwt_identity()
    data = request.get_json() or {}
    print(f"📝 update_annotation {aid} by user_id={identity} data:", data)
    a = Annotation.query.get_or_404(aid)
    if 'name' in data:
        a.name = data['name']
    if data.get('geojson',{}).get('geometry'):
        poly = shape(data['geojson']['geometry'])
        a.geom = from_shape(poly, srid=4326)
    db.session.commit()
    print(f"✅ Updated annotation id={aid}")
    return jsonify({'status':'ok'})

@app.route('/annotations/<int:aid>', methods=['DELETE'])
@jwt_required()
def delete_annotation(aid):
    identity = get_jwt_identity()
    print(f"🗑 delete_annotation {aid} by user_id={identity}")
    a = Annotation.query.get_or_404(aid)
    db.session.delete(a); db.session.commit()
    print(f"✅ Deleted annotation id={aid}")
    return jsonify({'status':'deleted'})

if __name__ == '__main__':
    app.run(debug=True)
