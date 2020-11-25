from api import db


class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(50),nullable=False,unique=True)
    username = db.Column(db.String(100),nullable=False,unique=True)
    password = db.Column(db.String(100),nullable=False)


class Todo(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    description = db.Column(db.Text)
    user_id = db.Column(db.String(50),nullable=False)
    complete = db.Column(db.Boolean)



