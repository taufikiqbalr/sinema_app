from flask import Flask, render_template, request, jsonify, abort, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from blockchain import Blockchain, Block
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
from datetime import datetime, timedelta
# import url_for

app = Flask(__name__)

# ─── Config ────────────────────────────────────────────────────────────────────
app.config['SQLALCHEMY_DATABASE_URI']       = 'postgresql://postgres:postgres@localhost/sinema_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY']                = 'rahasianegara'
app.config['JWT_ACCESS_TOKEN_EXPIRES']      = timedelta(minutes=15)

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
    province_id = db.Column(UUID(as_uuid=True), db.ForeignKey('provinces.id'), nullable=False)
    city_id     = db.Column(UUID(as_uuid=True), db.ForeignKey('cities.id'), nullable=False)
    place_type_id = db.Column(UUID(as_uuid=True), db.ForeignKey('place_types.id'), nullable=False)
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
class Province(db.Model):
    __tablename__ = 'provinces'
    id   = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String, nullable=False)

class City(db.Model):
    __tablename__ = 'cities'
    id            = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    province_id   = db.Column(UUID(as_uuid=True), db.ForeignKey('provinces.id'), nullable=False)
    name          = db.Column(db.String, nullable=False)

class PlaceType(db.Model):
    __tablename__ = 'place_types'
    id   = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String, nullable=False)

class BlockRecord(db.Model):
    """Persists every mined blockchain block to PostgreSQL."""
    __tablename__ = 'blockchain_blocks'
    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    blk_index     = db.Column(db.Integer, nullable=False, unique=True)
    timestamp     = db.Column(db.Float,   nullable=False)
    data          = db.Column(db.JSON,    nullable=False)   # full transaction dict
    previous_hash = db.Column(db.String,  nullable=False)
    nonce         = db.Column(db.Integer, nullable=False)
    block_hash    = db.Column(db.String,  nullable=False)

# ─── Conditional table creation ────────────────────────────────────────────────
with app.app_context():
     inspector = inspect(db.engine)
     for model in (Province, City, PlaceType, Annotation, User, AnnotationPhoto, BlockRecord):
         if not inspector.has_table(model.__tablename__):
             model.__table__.create(db.engine)
             print(f"🛠 Created missing table '{model.__tablename__}'")


# ─── Blockchain helpers ────────────────────────────────────────────────────────
def _load_chain() -> Blockchain:
    """Rebuild the in-memory Blockchain from stored BlockRecord rows."""
    bc = Blockchain()
    rows = BlockRecord.query.order_by(BlockRecord.blk_index).all()
    bc.load([
        {
            "index":         r.blk_index,
            "timestamp":     r.timestamp,
            "data":          r.data,
            "previous_hash": r.previous_hash,
            "nonce":         r.nonce,
            "hash":          r.block_hash,
        }
        for r in rows
    ])
    return bc


def _persist_block(block: Block) -> None:
    """Save a freshly mined Block to the database."""
    rec = BlockRecord(
        blk_index     = block.index,
        timestamp     = block.timestamp,
        data          = block.data,
        previous_hash = block.previous_hash,
        nonce         = block.nonce,
        block_hash    = block.hash,
    )
    db.session.add(rec)
    db.session.commit()
    print(f"⛏  Mined block #{block.index} hash={block.hash[:16]}… nonce={block.nonce}")


def blockchain_record(action: str, annotation_id: str, payload: dict) -> None:
    """High-level helper: load chain, mine a new block, persist it."""
    bc = _load_chain()
    genesis = bc.ensure_genesis()
    if genesis:
        _persist_block(genesis)
    block = bc.add_block(action, annotation_id, payload)
    _persist_block(block)

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

@app.route('/provinces_manage')
def provinces_page():
    return render_template('provinces.html')

@app.route('/cities_manage')
def cities_page():
    return render_template('cities.html')

@app.route('/place_types_manage')
def place_types_page():
    return render_template('place_types.html')

@app.route('/blockchain_manage')
def blockchain_page():
    return render_template('blockchain.html')

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

@app.route('/refresh_token', methods=['POST'])
@jwt_required()
def refresh_token():
    """Issue a fresh access token for the currently authenticated user."""
    identity = get_jwt_identity()
    new_token = create_access_token(identity=identity)
    print(f"🔄 Token refreshed for user_id={identity}")
    return jsonify({'access_token': new_token})

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

# ─── Provinces CRUD APIs ──────────────────────────────────────────────────────
@app.route('/provinces', methods=['GET'])
@jwt_required()
def list_provinces():
    return jsonify([{'id': str(p.id), 'name': p.name} for p in Province.query.all()])

@app.route('/provinces', methods=['POST'])
@jwt_required()
def create_province():
    data = request.get_json() or {}
    p = Province(name=data['name'])
    db.session.add(p); db.session.commit()
    return jsonify({'id': str(p.id), 'name': p.name}), 201

@app.route('/provinces/<string:pid>', methods=['PUT'])
@jwt_required()
def update_province(pid):
    p = Province.query.get_or_404(pid)
    data = request.get_json() or {}
    if 'name' in data:
        p.name = data['name']
        db.session.commit()
    return jsonify({'id': str(p.id), 'name': p.name})

@app.route('/provinces/<string:pid>', methods=['DELETE'])
@jwt_required()
def delete_province(pid):
    p = Province.query.get_or_404(pid)
    db.session.delete(p); db.session.commit()
    return jsonify({'status':'deleted'})

# ─── Cities CRUD APIs ──────────────────────────────────────────────────────────
@app.route('/cities', methods=['GET'])
@jwt_required()
def list_cities():
    return jsonify([
        {'id': str(c.id), 'name': c.name, 'province_id': str(c.province_id)}
        for c in City.query.all()
    ])

@app.route('/cities', methods=['POST'])
@jwt_required()
def create_city():
    data = request.get_json() or {}
    c = City(name=data['name'], province_id=data['province_id'])
    db.session.add(c); db.session.commit()
    return jsonify({'id': str(c.id), 'name': c.name, 'province_id': str(c.province_id)}), 201

@app.route('/cities/<string:cid>', methods=['PUT'])
@jwt_required()
def update_city(cid):
    c = City.query.get_or_404(cid)
    data = request.get_json() or {}
    if 'name' in data: c.name = data['name']
    if 'province_id' in data: c.province_id = data['province_id']
    db.session.commit()
    return jsonify({'id': str(c.id), 'name': c.name, 'province_id': str(c.province_id)})

@app.route('/cities/<string:cid>', methods=['DELETE'])
@jwt_required()
def delete_city(cid):
    c = City.query.get_or_404(cid)
    db.session.delete(c); db.session.commit()
    return jsonify({'status':'deleted'})

# ─── Place Types CRUD APIs ─────────────────────────────────────────────────────
@app.route('/place_types', methods=['GET'])
@jwt_required()
def list_place_types():
    return jsonify([{'id': str(pt.id), 'name': pt.name} for pt in PlaceType.query.all()])

@app.route('/place_types', methods=['POST'])
@jwt_required()
def create_place_type():
    data = request.get_json() or {}
    pt = PlaceType(name=data['name'])
    db.session.add(pt); db.session.commit()
    return jsonify({'id': str(pt.id), 'name': pt.name}), 201

@app.route('/place_types/<string:ptid>', methods=['PUT'])
@jwt_required()
def update_place_type(ptid):
    pt = PlaceType.query.get_or_404(ptid)
    data = request.get_json() or {}
    if 'name' in data: pt.name = data['name']
    db.session.commit()
    return jsonify({'id': str(pt.id), 'name': pt.name})

@app.route('/place_types/<string:ptid>', methods=['DELETE'])
@jwt_required()
def delete_place_type(ptid):
    pt = PlaceType.query.get_or_404(ptid)
    db.session.delete(pt); db.session.commit()
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
                'province_id':   str(a.province_id),
                'city_id':       str(a.city_id),
                'place_type_id': str(a.place_type_id),
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
      province_id         = data['province_id'],
      city_id             = data['city_id'],
      place_type_id       = data['place_type_id'],
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
    blockchain_record(
        action        = "INSERT",
        annotation_id = str(ann.id),
        payload       = {
            'name':                ann.name,
            'province_id':         str(ann.province_id),
            'city_id':             str(ann.city_id),
            'place_type_id':       str(ann.place_type_id),
            'occurrence_location': ann.occurrence_location,
            'occurrence_date':     ann.occurrence_date.isoformat(),
            'area_condition':      ann.area_condition,
            'landslide_condition': ann.landslide_condition,
            'landslide_impact':    ann.landslide_impact,
            'causative_factor':    ann.causative_factor,
            'mechanism':           ann.mechanism,
        },
    )
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
      'province_id','city_id','place_type_id',
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
    blockchain_record(
        action        = "UPDATE",
        annotation_id = str(aid),
        payload       = {
            'name':                a.name,
            'province_id':         str(a.province_id),
            'city_id':             str(a.city_id),
            'place_type_id':       str(a.place_type_id),
            'occurrence_location': a.occurrence_location,
            'occurrence_date':     a.occurrence_date.isoformat() if a.occurrence_date else None,
            'area_condition':      a.area_condition,
            'landslide_condition': a.landslide_condition,
            'landslide_impact':    a.landslide_impact,
            'causative_factor':    a.causative_factor,
            'mechanism':           a.mechanism,
        },
    )
    return jsonify({'status':'ok'})

@app.route('/annotations/<string:aid>', methods=['DELETE'])
@jwt_required()
def delete_annotation(aid):
    identity = get_jwt_identity()
    print(f"🗑 delete_annotation {aid} by user_id={identity}")
    a = Annotation.query.get_or_404(aid)
    snapshot = {
        'name':                a.name,
        'province_id':         str(a.province_id),
        'city_id':             str(a.city_id),
        'place_type_id':       str(a.place_type_id),
        'occurrence_location': a.occurrence_location,
        'occurrence_date':     a.occurrence_date.isoformat() if a.occurrence_date else None,
        'area_condition':      a.area_condition,
        'landslide_condition': a.landslide_condition,
        'landslide_impact':    a.landslide_impact,
        'causative_factor':    a.causative_factor,
        'mechanism':           a.mechanism,
    }
    db.session.delete(a); db.session.commit()
    print(f"✅ Deleted annotation id={aid}")
    blockchain_record(action="DELETE", annotation_id=str(aid), payload=snapshot)
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

# ─── Blockchain API ───────────────────────────────────────────────────────────
@app.route('/blockchain_chain', methods=['GET'])
@jwt_required()
def get_blockchain():
    """Return the full blockchain as JSON, plus a validity flag."""
    bc = _load_chain()
    bc.ensure_genesis()   # no-op if chain is populated
    return jsonify({
        'valid':  bc.is_valid(),
        'length': len(bc.chain),
        'chain':  [b.to_dict() for b in bc.chain],
    })


if __name__ == '__main__':
    app.run(debug=True)
