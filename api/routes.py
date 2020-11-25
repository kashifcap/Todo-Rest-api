from flask import jsonify,make_response,request
from api import app,db
from api.models import User,Todo
from api.schema import user_schema, todo_schema, todos_schema
import uuid
from werkzeug.security import generate_password_hash, check_password_hash



@app.route('/register', methods = ['POST'])
def register():
    data = request.get_json()

    if not data or not data['name'] or not data['password']:
        return jsonify({'msg' : 'Invalid data!'})
    
    if User.query.filter_by(username=data['name']).first():
        return jsonify({'msg' : 'Username already taken!'})
    
    hashed_pswd = generate_password_hash(data['password'], method='sha256')

    user = User(public_id=str(uuid.uuid4()),username=data['name'],password=hashed_pswd)

    db.session.add(user)
    db.session.commit()

    return_schema = user_schema.dump(user)

    return jsonify({'message': 'User added successfully', 'user': return_schema})
    