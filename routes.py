from flask import request, jsonify, Blueprint
from create_app import db, bcrypt
from models import User, Event
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

auth = Blueprint('auth', __name__)
events = Blueprint('events', __name__)

@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], email=data['email'], password=hashed_password)
    try:
        db.session.add(user)
        db.session.commit()
        return jsonify(message="User registered"), 201
    except Exception as e:
        print(f"Error: {e}")
        return jsonify(message="Error registering user"), 500


@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify(message="Invalid credentials"), 401

@events.route('/events', methods=['POST'])
@jwt_required()
def create_event():
    data = request.get_json()
    user_id = get_jwt_identity()
    event = Event(title=data['title'], description=data['description'], date=data['date'], user_id=user_id)
    db.session.add(event)
    db.session.commit()
    return jsonify(message="Event created"), 201

@events.route('/events', methods=['GET'])
def get_events():
    events = Event.query.all()
    result = []
    for event in events:
        event_data = {
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'date': event.date
        }
        result.append(event_data)
    return jsonify(result), 200
