from app import app, lm
from flask import request, session, make_response
from flask_login import login_user, logout_user, login_required
from .user import User
from bson import json_util, ObjectId
import json
import base64
import logging

@app.route('/login', methods=['POST'])
def login():
    response = {
        "response": ""
    }
    username = request.json.get('username')
    password = request.json.get('password')
    if username and password:
        user = app.mongo.db.user.find_one({"username": username})
        if user and User.validate_login(user["password_hash"], password):
            user_obj = User.build_user(user)
            if login_user(user_obj):
                userSession = {
                    'userId': user['_id'],
                    'session_id': session["_id"],
                }
                app.mongo.db.session.insert(userSession)
                app.mongo.db.session.update({
                    "userId" : ObjectId(user['_id'])
                },
                {
                    "$set": {
                        "session_id": session['_id']
                    }
                }, upsert=True)
                return make_response(json_util.dumps(userSession),200)
        else:
            response["response"] = "Worng password"
            return make_response(json.dumps(response),400)
    else:
        response["response"] = "Username or password not entered"
        return make_response(json.dumps(response),400)

@app.route('/logout')
def logout():

    response = {
        "response": ""
    }
    api_key = request.headers.get('Authorization')
    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            deleteUser = app.mongo.db.session.remove({'_id': userFromSession['_id']}, True)
            if deleteUser:
                status_code = 200
                response['response'] = "User logged out"
            else:
                status_code = 400
                response['response'] = "Something went wrong"
        else:
            status_code = 200
            response['response'] = "User has already logged out"

        logout_user()
    return make_response(json.dumps(response),status_code)

@app.route('/write', methods=['GET'])
@login_required
def write():
    return make_response(json.dumps({"success": True}),200)

@lm.request_loader
def load_user_from_request(request):
    api_key = request.headers.get('Authorization')
    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key)
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {
                "session_id": api_key
            })
        if userFromSession:
            user = app.mongo.db.user.find_one(
                {
                    "_id": ObjectId(userFromSession['userId'])
                })

            user_obj = User.build_user(user)
            if user_obj:
                return user_obj
            else:
                return None
        else:
            return None

@app.route('/register', methods=['POST'])
def new_user():
    response = {
        "response": ""
    }
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')

    if username is None or password is None or username == "" or password == "":
        response["response"] = "username or password not provided"
        return make_response(json.dumps(response), 400)

    if app.mongo.db.user.find_one({"username": username}) is not None:
        response["response"] = "username taken"
        return make_response(json.dumps(response), 400)

    user = User("")
    user.username = username
    user.hash_password(password = password)
    user.set_email(email = email)

    if user.save():
        response["response"] = "User saved"
        response["userId"] = user.id
        response = json.dumps(response, default=json_util.default)
    return make_response(json.dumps(response), 200)


@app.route('/addItem', methods=['POST'])
def add_to_cart():
    item_id = request.json.get('item_id')
    api_key = request.headers.get('Authorization')

    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            add_item = app.mongo.db.session.update({'_id': userFromSession['_id']}, {"$push": {"cart_list":[item_id]}})
            if add_item:
                status_code = 200
                response['response'] = "Added complete"
            else:
                status_code = 400
                response['response'] = "Something went wrong"
        else:
            status_code = 200
            response['response'] = "User has not logged in"

# all item from certain collector
@app.route('/allItem', methods=['POST'])
def get_all_item():
    offset = request.json.get('offset')
    length = request.json.get('length')
    collector = request.json.get('collector_id')

# collector list
@app.route('/allCollector', methods=['POST'])
def get_all_collector():
    offset = request.json.get('offset')
    length = request.json.get('length')


