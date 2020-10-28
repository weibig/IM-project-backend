from app import app, lm
from flask import request, session, make_response
from flask_login import login_user, logout_user, login_required
from .user import User, Product
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
                    "userId": ObjectId(user['_id'])
                },
                    {
                    "$set": {
                        "session_id": session['_id']
                    }
                }, upsert=True)
                return make_response(json_util.dumps(userSession), 200)
        else:
            response["response"] = "Worng password"
            return make_response(json.dumps(response), 400)
    else:
        response["response"] = "Username or password not entered"
        return make_response(json.dumps(response), 400)


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
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        if userFromSession:
            deleteUser = app.mongo.db.session.remove(
                {'_id': userFromSession['_id']}, True)
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
    return make_response(json.dumps(response), status_code)


@app.route('/write', methods=['GET'])
@login_required
def write():
    return make_response(json.dumps({"success": True}), 200)


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
def register():
    response = {
        "response": ""
    }
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')

    if username is None or password is None or username == "" or password == "":
        response["response"] = "username or password not provided"
        return make_response(json.dumps(response), 400)

    if app.mongo.db.user.find_one({"username": username}):
        response["response"] = "Username has been taken"
        return make_response(json.dumps(response), 400)

    user = User("")
    user.username = username
    user.hash_password(password=password)
    user.set_email(email=email)

    if user.save():
        response["response"] = "User saved"
        response["userId"] = user["_id"]
        response = json.dumps(response, default=json_util.default)
    return make_response(json.dumps(response), 200)


@app.route('/addChart', methods=['POST'])
def add_to_cart():
    response = {
        "response": ""
    }
    status_code = 200
    item_id = request.json.get('item_id')
    api_key = request.headers.get('Authorization')

    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        if userFromSession:
            add_item = app.mongo.db.session.update({'_id': userFromSession['_id']}, {
                                                   "$push": {"cart_list": [item_id]}})
            if add_item:
                response['response'] = "Added complete"
            else:
                status_code = 400
                response['response'] = "Something went wrong"
        else:
            response['response'] = "User has not logged in"
    else:
        status_code = 400
        response['response'] = "Authorization error"
    return make_response(json.dumps(response), status_code)

# add item to his selling list


@app.route('/addProduct', methods=['POST'])
def add_to_selling_list():
    response = {
        "response": ""
    }
    status_code = 200
    # user info
    api_key = request.headers.get('Authorization')

    # item info
    name = request.json.get('name')
    image_urls = request.json.get('image_urls')
    description = request.json.get('description')
    price = request.json.get('price')

    # create item

    if name is None or price is None or name == "" or price == "":
        response["response"] = "item's name or price is not provided"
        return make_response(json.dumps(response), 400)

    if app.mongo.db.product.find_one({"name": name}):
        response["response"] = "item name has been used by this user"
        return make_response(json.dumps(response), 400)

    user = Product("")
    user.username = username
    user.hash_password(password=password)
    user.set_email(email=email)

    if user.save():
        response["response"] = "User saved"
        response["userId"] = user["_id"]
        response = json.dumps(response, default=json_util.default)

    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        if userFromSession:
            add_item = app.mongo.db.session.update({'_id': userFromSession['_id']}, {
                                                   "$push": {"sell_list": [item_id]}})
            if add_item:
                response['response'] = "Added complete"
            else:
                status_code = 400
                response['response'] = "Something went wrong"
        else:
            response['response'] = "User has not logged in"
    else:
        status_code = 400
        response['response'] = "Authorization error"
    return make_response(json.dumps(response), status_code)


# all selling item from certain collector
@app.route('/sellList', methods=['POST'])
def get_sell_list():
    response = {
        "response": ""
    }
    offset = request.json.get('offset')
    length = request.json.get('length')
    userId = request.json.get('userId')  # collector's user id

    checkUser = app.mongo.db.user.find_one({"id": userId})
    if checkUser:
        sell_list = checkUser['sell_list'][offset:offset+length]
        response["sell_list"] = sell_list
        response["total_length"] = len(checkUser['sell_list'])
        response["response"] = "successful"
        return make_response(json.dumps(response), 200)
    else:
        response["response"] = "User ID not found"
        return make_response(json.dumps(response), 400)


@app.route('/allCollector', methods=['POST'])  # collector list
def get_all_collector():
    offset = request.json.get('offset')
    length = request.json.get('length')
    checkCollector = app.mongo.db.user.find({$expr: "this.sell_list.length > 0"})
