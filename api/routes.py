from flask import jsonify,make_response,request
from api import app,db
from api.models import User,Todo
from api.schema import user_schema, todo_schema, todos_schema
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            print("token not present")
            return jsonify({'msg' : 'Invalid Token!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            print("corrupted token")
            return jsonify({'msg' : 'Invalid Token!'}), 401
        
        if not current_user:
            print("user not associated with toke")
            return jsonify({'msg' : 'Invalid Token'}), 401
        
        return f(current_user, *args,**kwargs)



    return decorated


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


@app.route('/login')
def login():
    data = request.authorization

    if not data or not data.username or not data.password:
        return jsonify({'msg' : 'Invalid Credentials!'}), 401
    
    user = User.query.filter_by(username=data.username).first()

    if not user:
        return jsonify({'msg' : 'Invalid Credentials!'}), 401
    
    if check_password_hash(user.password, data.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'msg' : 'Login success', 'x-access-token' : token.decode('UTF-8')})
    
    return jsonify({'msg' : 'Invalid Credentials!'}), 401


@app.route('/todo', methods=['GET'])
@token_required
def get_todo(current_user):
    todo = Todo.query.filter_by(user_id = current_user.public_id)

    result = todos_schema.dump(todo)

    return jsonify(result)


@app.route('/todo', methods=['POST'])
@token_required
def add_todo(current_user):
    data = request.get_json()

    todo = Todo(description=data['description'],complete=False,user_id=current_user.public_id)

    db.session.add(todo)
    db.session.commit()

    result = todo_schema.dump(todo)

    return jsonify({'msg' : 'Todo Created', 'Todo' : result})


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user,todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()

    if todo.user_id != current_user.public_id:
        return jsonify({'msg' : 'Permission denied!'}), 401
    
    todo.complete = True
    db.session.commit()

    result = todo_schema.dump(todo)

    return jsonify({'msg' : 'Todo completed', 'Todo' : result})
