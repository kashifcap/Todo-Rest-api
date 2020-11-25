from api import ma


class UserSchema(ma.Schema):
    class Meta:
        fields = ('public_id', 'username','password')


class TodoSchema(ma.Schema):
    class Meta:
        fields = ('id','description','user_id','complete')

user_schema = UserSchema()
todo_schema = TodoSchema()
todos_schema = TodoSchema(many=True)