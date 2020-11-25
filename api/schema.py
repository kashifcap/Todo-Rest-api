from api import Marshmallow


class UserSchema(ma.Schema):
    class Meta:
        fields = ('public_id', 'username','password')


class TodoSchema(ma.Schema):
    class Meta:
        fields = ('id','description','user_id','complete')

