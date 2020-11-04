from app import app, lm
from flask import request, session, make_response
from flask_login import login_user, logout_user, login_required
from .models import User, Product
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

    if username is None or password is None or username == "" or password == "":
        response["response"] = "username or password is not provided"
        return make_response(json.dumps(response), 400)

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
        response["response"] = "username or password is not provided"
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
        response["userId"] = user.id
        response = json.dumps(response, default=json_util.default)
    return make_response(response, 200)


@app.route('/addChart', methods=['POST'])
def add_to_cart():
    response = {
        "response": ""
    }
    status_code = 200
    item_id = request.json.get('item_id')
    api_key = request.headers.get('Authorization')

    if item_id is None:
        response["response"] = "Item ID is not provided"
        return make_response(json.dumps(response), 400)

    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        if userFromSession:
            add_item = app.mongo.db.user.findAndModify({
                "query": { '_id': userFromSession['userId'] },
                "update": { "$inc": { "cart_list."+item_id: 1 } },
                "upsert": "true"
            })
            # add_item = app.mongo.db.user.update({'_id': userFromSession['userId']}, {
            #                                        "$push": {"cart_list": item_id}})
            if add_item:
                response['response'] = "Add chart complete"
            else:
                status_code = 400
                response['response'] = "Something went wrong"
        else:
            response['response'] = "User has not logged in"
    else:
        status_code = 400
        response['response'] = "Authorization error"
    return make_response(json.dumps(response), status_code)

@app.route('/removeChart', methods=['POST'])
def remove_to_cart():
    response = {
        "response": ""
    }
    status_code = 200
    item_id = request.json.get('item_id')
    api_key = request.headers.get('Authorization')

    if item_id is None:
        response["response"] = "Item ID is not provided"
        return make_response(json.dumps(response), 400)

    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        if userFromSession:
            remove_item = app.mongo.db.user.findAndModify({
                "query": { '_id': userFromSession['userId'] },
                "update": { "$inc": { "cart_list."+item_id: -1 } }
            })
            # remove_item = app.mongo.db.user.update({'_id': userFromSession['userId']}, {
            #                                        "$pull": {"cart_list": item_id}})
            if remove_item:
                response['response'] = "Remove chart complete"
            else:
                status_code = 400
                response['response'] = "Something went wrong"
        else:
            response['response'] = "User has not logged in"
    else:
        status_code = 400
        response['response'] = "Authorization error"
    return make_response(json.dumps(response), status_code)

# add item to his sell list
@app.route('/addProduct', methods=['POST'])
def add_product():
    response = {}
    status_code = 200
    
    # user info
    api_key = request.headers.get('Authorization')

    # item info
    name = request.json.get('name')
    image_urls = request.json.get('image_urls',default=[])
    description = request.json.get('description',default="")
    price = request.json.get('price')

    # create item
    if name is None or price is None or name == "" or price == "":
        response["response"] = "item's name or price is not provided"
        return make_response(json.dumps(response), 400)

    product = Product(id="",name=name,image_urls=image_urls,description=description,price=price)
    
    #check user auth
    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        if userFromSession:
            product.setOwner(userFromSession['userId'])

            # save product + store in user's sell list
            if product.save():
                response["product_response"] = "product saved"
                response["productId"] = product.id
                # response = json.dumps(response, default=json_util.default)
                
                add_item = app.mongo.db.user.findAndModify({
                    "query": { '_id': userFromSession['userId'] },
                    "update": { "$inc": { "sell_list."+product.id: 1 } },
                    "upsert": "true"
                })
                # add_item = app.mongo.db.user.update({'_id': userFromSession['userId']}, {
                #                                    "$push": {"sell_list": product.id}})
                                                   
                if add_item:
                    response['response'] = "Add product complete"
                else:
                    status_code = 400
                    response['response'] = "Add product to user's sell list error"
                
            else:
                status_code = 400
                response['response'] = "Add product error"
        else:
            response['response'] = "User has not logged in"
    else:
        status_code = 400
        response['response'] = "Authorization error"
    
    return make_response(json.dumps(response, default=json_util.default), status_code)

# revise item to his sell list
@app.route('/reviseProduct', methods=['POST'])
def revise_product():
    response = {}
    status_code = 200
    
    # user info
    api_key = request.headers.get('Authorization')

    # item info
    item_id = request.json.get('item_id')
    name = request.json.get('name')
    image_urls = request.json.get('image_urls')
    description = request.json.get('description')
    price = request.json.get('price')

    # create item
    if item_id is None:
        response["response"] = "item's id is not provided"
        return make_response(json.dumps(response), 400)
    
    #check user auth
    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        isOwner = app.mongo.db.product.find_one({"_id": item_id, "owner": userFromSession['userId']})
        if userFromSession and isOwner:
            ### TODO update method
            revise_item = app.mongo.db.product.findAndModify({
                "query": { '_id': item_id },
                "update": {'name': name, }
            })                                  
            if revise_item:
                response['response'] = "Revise product complete"
            else:
                status_code = 400
                response['response'] = "Revise product error"
        else:
            response['response'] = "User has no authentication"
    else:
        status_code = 400
        response['response'] = "Authorization error"
    
    return make_response(json.dumps(response, default=json_util.default), status_code)

# remove item from his sell list
@app.route('/removeProduct', methods=['POST'])
def remove_product():
    response = {
        "response": ""
    }
    status_code = 200
    item_id = request.json.get('item_id')
    api_key = request.headers.get('Authorization')

    if item_id is None:
        response["response"] = "Item ID is not provided"
        return make_response(json.dumps(response), 400)

    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key).decode('utf-8')
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one(
            {"session_id": api_key})
        isOwner = app.mongo.db.product.find_one({"_id": item_id, "owner": userFromSession['userId']})
        if userFromSession and isOwner:
            remove_from_sell_list = app.mongo.db.user.findAndModify({
                "query": { '_id': userFromSession['userId'] },
                "update": { "$inc": { "sell_list."+item_id: -1 } }
            })
            remove_item = app.mongo.db.product.remove({"_id": item_id})

            # remove_item = app.mongo.db.user.update({'_id': userFromSession['userId']}, {
            #                                        "$pull": {"sell_list": item_id}})
            if remove_from_sell_list and remove_item:
                response['response'] = "Remove product complete"
            else:
                status_code = 400
                response['response'] = "Something went wrong"
        else:
            response['response'] = "User has no authentication"
    else:
        status_code = 400
        response['response'] = "Authorization error"
    return make_response(json.dumps(response), status_code)


@app.route('/allCollector', methods=['POST'])  # collector list
def get_all_collector():
    collectors = []
    offset = int(request.json.get('offset')) if request.json.get('offset') else 0
    length = int(request.json.get('length')) if request.json.get('length') else 0
    for r in app.mongo.db.user.find({"sell_list.0": {"$exists": "true"}}):
        collectors.append(r['_id'])

    if offset > len(collectors):
        response = {"response": "invalid offset"}
        return make_response(json.dumps(response), 400)

    if offset+length > len(collectors) or length == 0:
        collectors = collectors[offset:]
    else:
        collectors = collectors[offset:offset+length]

    response = {"collectors": collectors, "response": "successful"}
    return make_response(json.dumps(response, default=json_util.default), 200)
    
@app.route('/userInfo', methods=['POST'])
def get_user_info():
    response = {}
    userId = request.json.get('userId')
    
    if userId is None:
        response["response"] = "User ID is not provided"
        return make_response(json.dumps(response), 400)

    checkUser = app.mongo.db.user.find_one({"_id": ObjectId(userId)})
    if checkUser:
        response["email"] = checkUser["email"]
        response["cart_list"] = checkUser["cart_list"]
        response["sell_list"] = checkUser["sell_list"]
        response["buy_list"] = checkUser["buy_list"]
        response["response"] = "successful"
        return make_response(json.dumps(response,default=json_util.default), 200)
    
    response["response"] = "User ID is not found"
    return make_response(json.dumps(response), 400)

@app.route('/itemInfo', methods=['POST'])
def get_item_info():
    response = {}
    itemId = request.json.get('itemId')
    
    if itemId is None:
        response["response"] = "Product ID is not provided"
        return make_response(json.dumps(response), 400)

    checkProduct = app.mongo.db.product.find_one({"_id": ObjectId(itemId)})
    if checkProduct:
        response["name"] = checkProduct["name"]
        response["image_urls"] = checkProduct["image_urls"]
        response["description"] = checkProduct["description"]
        response["price"] = checkProduct["price"]
        response["owner"] = checkProduct["owner"]
        response["response"] = "successful"
        return make_response(json.dumps(response,default=json_util.default), 200)
    
    response["response"] = "Product ID is not found"
    return make_response(json.dumps(response), 400)