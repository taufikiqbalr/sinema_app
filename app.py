from flask import Flask, render_template, request, jsonify, abort, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
import os
import uuid
from sqlalchemy.dialects.postgresql import UUID
from geoalchemy2 import Geometry
from geoalchemy2.shape import from_shape, to_shape
from shapely.geometry import shape
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
# import url_for

app = Flask(__name__)

# ─── Config ────────────────────────────────────────────────────────────────────
app.config['SQLALCHEMY_DATABASE_URI']       = 'postgresql://postgres:root@localhost/mymapdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY']                = 'rahasianegara'

db  = SQLAlchemy(app)
jwt = JWTManager(app)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXT = {'png','jpg','jpeg','gif'}

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
    id   = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String, nullable=False)
    occurrence_location  = db.Column(db.String, nullable=False)
    occurrence_date      = db.Column(db.Date,   nullable=False)
    area_condition       = db.Column(db.String, nullable=False)
    landslide_condition  = db.Column(db.String, nullable=False)
    landslide_impact     = db.Column(db.String, nullable=False)
    causative_factor     = db.Column(db.String, nullable=False)
    mechanism            = db.Column(db.String, nullable=False)
    geom = db.Column(Geometry('POLYGON', srid=4326), nullable=False)

class AnnotationPhoto(db.Model):
    __tablename__ = 'annotation_photos'
    id            = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    annotation_id = db.Column(UUID(as_uuid=True), db.ForeignKey('annotations.id'), nullable=False)
    filename      = db.Column(db.String, nullable=False)

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
     for model in (Annotation, User, AnnotationPhoto):
         if not inspector.has_table(model.__tablename__):
             model.__table__.create(db.engine)
             print(f"🛠 Created missing table '{model.__tablename__}'")

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
        # skip any without geometry
        if a.geom is None:
            print(f"⚠️ Skipping annotation id={a.id} with no geom")
            continue
        try:
            geo = to_shape(a.geom).__geo_interface__
        except Exception as e:
            print(f"⚠️ Error decoding geom for id={a.id}: {e}")
            continue
        
        # collect photo URLs
        photo_urls = [
            url_for('static', filename=f'uploads/{p.filename}')
            for p in AnnotationPhoto.query.filter_by(annotation_id=a.id)
        ]
        feats.append({
            'type': 'Feature',
            'id': str(a.id),
            'properties': {
              'name': a.name,
              'occurrence_location':  a.occurrence_location,
              'occurrence_date':      a.occurrence_date.isoformat(),
              'area_condition':       a.area_condition,
              'landslide_condition':  a.landslide_condition,
              'landslide_impact':     a.landslide_impact,
              'causative_factor':     a.causative_factor,
              'mechanism':            a.mechanism,
              'photos': photo_urls
            },
            'geometry': geo
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
    ann = Annotation(
      name                 = data.get('name','Unnamed'),
      geom                 = geom,
      occurrence_location  = data['occurrence_location'],
      occurrence_date      = data['occurrence_date'],
      area_condition       = data['area_condition'],
      landslide_condition  = data['landslide_condition'],
      landslide_impact     = data['landslide_impact'],
      causative_factor     = data['causative_factor'],
      mechanism            = data['mechanism']
    )
    db.session.add(ann); db.session.commit()
    print(f"✅ Saved annotation id={ann.id}")
    return jsonify({'status':'ok','id':ann.id})

@app.route('/annotations/<string:aid>', methods=['PUT'])
@jwt_required()
def update_annotation(aid):
    identity = get_jwt_identity()
    data = request.get_json() or {}
    print(f"📝 update_annotation {aid} by user_id={identity} data:", data)
    a = Annotation.query.get_or_404(aid)
    for field in (
      'name','occurrence_location','occurrence_date',
      'area_condition','landslide_condition',
      'landslide_impact','causative_factor','mechanism'
    ):
        if field in data:
            setattr(a, field, data[field])
    if data.get('geojson',{}).get('geometry'):
        poly = shape(data['geojson']['geometry'])
        a.geom = from_shape(poly, srid=4326)
    db.session.commit()
    print(f"✅ Updated annotation id={aid}")
    return jsonify({'status':'ok'})

@app.route('/annotations/<string:aid>', methods=['DELETE'])
@jwt_required()
def delete_annotation(aid):
    identity = get_jwt_identity()
    print(f"🗑 delete_annotation {aid} by user_id={identity}")
    a = Annotation.query.get_or_404(aid)
    db.session.delete(a); db.session.commit()
    print(f"✅ Deleted annotation id={aid}")
    return jsonify({'status':'deleted'})

# ─── New endpoint: upload photos ─────────────────────────────────────────────
@app.route('/annotations/<string:aid>/photos', methods=['POST'])
@jwt_required()
def upload_photos(aid):
    """Accepts multipart form-data files under 'photos' and attaches them."""
    # ensure annotation exists
    ann = Annotation.query.get_or_404(aid)
    files = request.files.getlist('photos')
    saved = []
    for f in files:
        ext = f.filename.rsplit('.',1)[-1].lower()
        if ext not in ALLOWED_EXT:
            continue
        fn = secure_filename(f"{uuid.uuid4()}.{ext}")
        path = os.path.join(UPLOAD_FOLDER, fn)
        f.save(path)
        photo = AnnotationPhoto(annotation_id=ann.id, filename=fn)
        db.session.add(photo)
        saved.append(fn)
    db.session.commit()
    # return URLs for client to render if desired
    urls = [ url_for('static', filename=f'uploads/{fn}') for fn in saved ]
    return jsonify({ 'uploaded': urls }), 201

if __name__ == '__main__':
    app.run(debug=True)
