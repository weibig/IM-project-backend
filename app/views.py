from app import app, lm
from flask import request, session, make_response
from flask_login import login_user, logout_user, login_required
from .models import User, Product
from bson import json_util, ObjectId
import json
import base64
import uuid
import logging
from web3 import Web3
import time
from eth_wallet.infura import Infura
from eth_account import Account
from eth_keys import keys
from mnemonic import Mnemonic
import codecs as codecs

@app.route("/login", methods=["POST"])
def login():
    response = {"response": ""}
    username = request.json.get("username")
    password = request.json.get("password")

    if username is None or password is None or username == "" or password == "":
        response["response"] = "username or password is not provided"
        return make_response(json.dumps(response), 400)

    user = app.mongo.db.user.find_one({"username": username})
    if user and User.validate_login(user["password_hash"], password):
        user_obj = User.build_user(user)
        session["uid"] = str(uuid.uuid4())
        if login_user(user_obj):
            userSession = {
                "userId": user["_id"],
                "session_id": session["uid"],
                "api_key": session["uid"].encode("utf-8"),
            }
            app.mongo.db.session.insert(userSession)
            app.mongo.db.session.update(
                {"userId": ObjectId(user["_id"])},
                {"$set": {"session_id": session["uid"]}},
                upsert=True,
            )
            return make_response(json_util.dumps(userSession), 200)
    else:
        response["response"] = "Worng password"
        return make_response(json.dumps(response), 400)


@app.route("/logout", methods=["POST"])
def logout():

    response = {"response": ""}
    api_key = request.headers.get("Authorization")
    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            deleteUser = app.mongo.db.session.remove(
                {"_id": userFromSession["uid"]}, True
            )
            if deleteUser:
                status_code = 200
                response["response"] = "User logged out"
            else:
                status_code = 400
                response["response"] = "Something went wrong"
        else:
            status_code = 200
            response["response"] = "User has already logged out"

        logout_user()
    return make_response(json.dumps(response), status_code)


@app.route("/write", methods=["GET"])
@login_required
def write():
    return make_response(json.dumps({"success": True}), 200)


@lm.request_loader
def load_user_from_request(request):
    api_key = request.headers.get("Authorization")
    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            user = app.mongo.db.user.find_one(
                {"_id": ObjectId(userFromSession["userId"])}
            )

            user_obj = User.build_user(user)
            if user_obj:
                return user_obj
            else:
                return None
        else:
            return None


@app.route("/register", methods=["POST"])
def register():
    response = {"response": ""}
    username = request.json.get("username")
    password = request.json.get("password")
    email = request.json.get("email")

    if username is None or password is None or username == "" or password == "":
        response["response"] = "username or password is not provided"
        return make_response(json.dumps(response), 400)

    if app.mongo.db.user.find_one({"username": username}):
        response["response"] = "Username has been taken"
        return make_response(json.dumps(response), 400)

    user = User("")
    user.username = username
    user.hash_password(password=password)
    user.wallet_address, user.priv_key = new_wallet()
    user.set_email(email=email)

    if user.save():
        response["response"] = "User saved"
        response["userId"] = user.id
        response = json.dumps(response, default=json_util.default)
    return make_response(response, 200)


@app.route("/addCart", methods=["POST"])
@login_required
def add_to_cart():
    response = {"response": ""}
    status_code = 200
    item_id = request.json.get("item_id")
    api_key = request.headers.get("Authorization")

    if item_id is None or (not ObjectId.is_valid(item_id)):
        response["response"] = "Item ID is not provided or format wrong"
        return make_response(json.dumps(response), 400)
    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            add_item = app.mongo.db.user.find_one_and_update(
                filter={"_id": userFromSession["userId"]},
                update={"$inc": {"cart_list." + item_id: 1}},
                upsert=True,
            )
            if add_item:
                response["response"] = "Add cart complete"
            else:
                status_code = 400
                response["response"] = "Something went wrong"
        else:
            status_code = 400
            response["response"] = "User has not logged in"
    else:
        status_code = 400
        response["response"] = "Authorization error"
    return make_response(json.dumps(response), status_code)


@app.route("/removeCart", methods=["POST"])
@login_required
def remove_to_cart():
    response = {"response": ""}
    status_code = 200
    item_id = request.json.get("item_id")
    api_key = request.headers.get("Authorization")

    if item_id is None or (not ObjectId.is_valid(item_id)):
        response["response"] = "Item ID is not provided or format wrong"
        return make_response(json.dumps(response), 400)

    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            remove_item = app.mongo.db.user.find_one_and_update(
                filter={
                    "_id": userFromSession["userId"],
                    "cart_list." + item_id: {"$gt": 0},
                },
                update={"$inc": {"cart_list." + item_id: -1}},
            )
            if remove_item:
                response["response"] = "Remove cart complete"
            else:
                status_code = 400
                response["response"] = "Something went wrong"
        else:
            status_code = 400
            response["response"] = "User has not logged in"
    else:
        status_code = 400
        response["response"] = "Authorization error"
    return make_response(json.dumps(response), status_code)


# add item to his sell list
@app.route("/addProduct", methods=["POST"])
@login_required
def add_product():
    response = {}
    status_code = 200

    # user info
    api_key = request.headers.get("Authorization")

    # item info
    name = request.json.get("name")
    image_urls = request.json.get("image_urls")
    description = request.json.get("description")
    price = request.json.get("price")

    if not image_urls:
        image_urls = []
    if not description:
        description = ""

    # create item
    if name is None or price is None or name == "" or price == "":
        response["response"] = "item's name or price is not provided"
        return make_response(json.dumps(response), 400)

    product = Product(
        id="", name=name, image_urls=image_urls, description=description, price=price
    )

    # check user auth
    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            product.setOwner(userFromSession["userId"])

            # save product + store in user's sell list
            if product.save():
                response["product_response"] = "product saved"
                response["productId"] = product.id

                add_item = app.mongo.db.user.find_one_and_update(
                    filter={"_id": userFromSession["userId"]},
                    update={"$inc": {"sell_list." + str(product.id): 1}},
                    upsert=True,
                )

                if add_item:
                    response["response"] = "Add product complete"
                else:
                    status_code = 400
                    response["response"] = "Add product to user's sell list error"

            else:
                status_code = 400
                response["response"] = "Add product error"
        else:
            status_code = 400
            response["response"] = "User has not logged in"
    else:
        status_code = 400
        response["response"] = "Authorization error"

    return make_response(json.dumps(response, default=json_util.default), status_code)


# revise item to his sell list
@app.route("/reviseProduct", methods=["POST"])
@login_required
def revise_product():
    response = {}
    status_code = 200

    # user info
    api_key = request.headers.get("Authorization")

    # item info
    item_id = request.json.get("item_id")
    name = request.json.get("name")
    image_urls = request.json.get("image_urls")
    description = request.json.get("description")
    price = request.json.get("price")
    amount = request.json.get("amount")

    # find item
    if item_id is None or (not ObjectId.is_valid(item_id)):
        response["response"] = "item's id is not provided"
        return make_response(json.dumps(response), 400)
    item_id = ObjectId(item_id)
    # set up updated item
    updated_item = {}
    if name:
        updated_item["name"] = name
    if image_urls:
        updated_item["image_urls"] = image_urls
    if description:
        updated_item["description"] = description
    if price:
        updated_item["price"] = price
    if amount:
        updated_item["amount"] = amount

    # check user auth
    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            isOwner = app.mongo.db.product.find_one(
                {"_id": item_id, "owner": userFromSession["userId"]}
            )
        else:
            isOwner = False
        if userFromSession and isOwner:
            revise_item = app.mongo.db.product.find_one_and_update(
                filter={"_id": item_id}, update={"$set": updated_item}
            )
            if revise_item:
                response["response"] = "Revise product complete"
            else:
                status_code = 400
                response["response"] = "Revise product error"
        else:
            response["response"] = "User has no authentication"
    else:
        status_code = 400
        response["response"] = "Authorization error"

    return make_response(json.dumps(response, default=json_util.default), status_code)


# remove item from his sell list
@app.route("/removeProduct", methods=["POST"])
@login_required
def remove_product():
    response = {"response": ""}
    status_code = 200
    item_id = request.json.get("item_id")
    api_key = request.headers.get("Authorization")

    if item_id is None or (not ObjectId.is_valid(item_id)):
        response["response"] = "Item ID is not provided or format wrong"
        return make_response(json.dumps(response), 400)
    item_id = ObjectId(item_id)
    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            isOwner = app.mongo.db.product.find_one(
                {"_id": item_id, "owner": userFromSession["userId"]}
            )
        else:
            isOwner = False
        if userFromSession and isOwner:
            remove_from_sell_list = app.mongo.db.user.find_one_and_update(
                filter={
                    "_id": userFromSession["userId"],
                    "sell_list." + str(item_id): {"$gt": 0},
                },
                update={"$unset": {"sell_list." + str(item_id): 1}},
            )
            remove_item = app.mongo.db.product.remove({"_id": item_id})
            if remove_from_sell_list and remove_item:
                response["response"] = "Remove product complete"
            else:
                status_code = 400
                response["response"] = "Something went wrong"
        else:
            response["response"] = "User has no authentication, you are " + str(
                userFromSession["userId"]
            )
    else:
        status_code = 400
        response["response"] = "Authorization error"
    return make_response(json.dumps(response), status_code)


@app.route("/allCollector", methods=["GET"])  # collector list
def get_all_collector():
    collectors = []
    offset = int(request.json.get("offset")) if request.json.get("offset") else 0
    length = int(request.json.get("length")) if request.json.get("length") else 0
    for r in app.mongo.db.user.find({"sell_list.0": {"$exists": "true"}}):
        collectors.append(r["_id"])

    if offset > len(collectors):
        response = {"response": "invalid offset"}
        return make_response(json.dumps(response), 400)

    if offset + length > len(collectors) or length == 0:
        collectors = collectors[offset:]
    else:
        collectors = collectors[offset : offset + length]

    response = {"collectors": collectors, "response": "successful"}
    return make_response(json.dumps(response, default=json_util.default), 200)


@app.route("/userInfo", methods=["GET"])
def get_user_info():
    response = {}
    userId = request.json.get("userId")

    if userId is None:
        response["response"] = "User ID is not provided"
        return make_response(json.dumps(response), 400)

    checkUser = app.mongo.db.user.find_one({"_id": ObjectId(userId)})
    if checkUser:
        response["email"] = checkUser["email"]
        response["wallet_address"] = checkUser["wallet_address"]
        response["cart_list"] = checkUser["cart_list"]
        response["sell_list"] = checkUser["sell_list"]
        # response["buy_list"] = checkUser["buy_list"]
        response["response"] = "successful"
        return make_response(json.dumps(response, default=json_util.default), 200)

    response["response"] = "User ID is not found"
    return make_response(json.dumps(response), 400)


@app.route("/itemInfo", methods=["GET"])
def get_item_info():
    response = {}
    itemId = request.json.get("itemId")

    if itemId is None:
        response["response"] = "Product ID is not provided"
        return make_response(json.dumps(response), 400)

    checkProduct = app.mongo.db.product.find_one({"_id": ObjectId(itemId)})
    if checkProduct:
        response["name"] = checkProduct["name"]
        response["image_urls"] = checkProduct["image_urls"]
        response["description"] = checkProduct["description"]
        response["price"] = checkProduct["price"]
        response["amount"] = checkProduct["amount"]
        response["owner"] = checkProduct["owner"]
        response["response"] = "successful"
        return make_response(json.dumps(response, default=json_util.default), 200)

    response["response"] = "Product ID is not found"
    return make_response(json.dumps(response), 400)

def new_wallet():
    mnemonic = Mnemonic("english")
    mnemonic_sentence = mnemonic.generate()

    seed = mnemonic.to_seed(mnemonic_sentence)
    master_private_key = seed[32:]

    account = Account.privateKeyToAccount(master_private_key)

    priv_key = keys.PrivateKey(master_private_key)
    pub_key = priv_key.public_key

    w3 = Infura().get_web3()
    return account.address, priv_key


@app.route("/confirmOrder", methods=["GET"])
def confirm_order():
    response = {"response": ""}

    api_key = request.headers.get("Authorization")

    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            user = app.mongo.db.user.find_one({"_id": userFromSession["userId"]})
            if user["cart_list"] != {}:
                # transform from cart_list to buy_list
                for itemId in user["cart_list"]:
                    amount = user["cart_list"][itemId]
                    checkProduct = app.mongo.db.product.find_one(
                        {"_id": ObjectId(itemId)}
                    )

                    if checkProduct["owner"] in buy_list:
                        buy_list[checkProduct["owner"]][itemId] = amount
                        buy_list[checkProduct["owner"]]["total"] += (
                            checkProduct["price"] * amount
                        )
                    else:
                        buy_list[checkProduct["owner"]] = {}
                        buy_list[checkProduct["owner"]][itemId] = amount
                        buy_list[checkProduct["owner"]]["total"] = (
                            checkProduct["price"] * amount
                        )
                # clean cart_list
                clean_cart = app.mongo.db.product.find_one_and_update(
                    filter={"_id": ObjectId(itemId)},
                    update={"$unset": {"cart_list": {}}},
                )
                for seller_id in buy_list.keys():
                    # update seller's inventory
                    error_product = []
                    success_data = buy_list[seller_id]
                    for product_id in buy_list[seller_id].keys():
                        updateInventory = app.mongo.db.user.find_one_and_update(
                            filter={
                                "_id": ObjectId(seller_id),
                                "sell_list." + str(product_id): {"$gt": buy_list[seller_id][product_id]}
                            },
                            update={"$inc": {"sell_list." + str(product_id): -int(buy_list[seller_id][product_id])}},
                        )
                        if not updateInventory:
                            error_product.append(product_id)
                            success_data.pop(product_id)

                    if len(error_product) != 0:
                        error_product_str = " ".join(error_product)
                        response["response"] = "Buying "+ seller_id + "'s " + error_product_str +" failed, other products succeed"  
                        return make_response(json.dumps(response), 400)
                    
                    # save successful transaction to blockchain
                    seller = app.mongo.db.user.find_one({"_id": ObjectId(seller_id)})
                    transaction_address = new_order(user.id, seller_id, success_data, seller['wallet_address'], seller['priv_key'])
                    updateTransaction = app.mongo.db.user.find_one_and_update(
                        filter={"_id": userFromSession["userId"]},
                        update={"$set": {"transaction_list." + str(transaction_address): "pending"}},
                        upsert=True
                    )
            else:
                response["response"] = "Cart is empty"
                return make_response(json.dumps(response), 400)
        else:
            response["response"] = "User has not logged in"
            return make_response(json.dumps(response), 400)
            
    else:
        response["response"] = "Authorization error"
        return make_response(json.dumps(response), 400)

    return make_response(json.dumps(response), 200)

# 將user['buy_list']存進block 回傳transaction's address, 同時由買家錢包轉錢至平台錢包
def new_order(buyer_id, seller_id, seller_buy_list, user_address, user_priv_key):
    w3 = Infura().get_web3()
    amount_in_ether = seller_buy_list['total']
    amount_in_wei = w3.toWei(amount_in_ether,'ether')

    acct = w3.eth.account.privateKeyToAccount(user_priv_key)

    input_data = {}
    input_data['data'] = seller_buy_list
    input_data['buyer'] = buyer_id
    input_data['seller'] = seller_id

    txn_dict = {
            'to': '0x12CaAe9aAF2bAEdB11471678232ad73bEF5C2889', # 平台錢包的 address
            'value': amount_in_wei,
            'gas': 4465030,
            'gasPrice': w3.toWei('21', 'gwei'),
            'from': user_address,
            'nonce': w3.eth.getTransactionCount(user_address),
            'data': input_data.encode('utf-8')
    }
    
    signed_txn = acct.signTransaction(txn_dict)
    txn_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    txReceipt = w3.eth.waitForTransactionReceipt(txn_hash)

    return txReceipt['transactionHash'].hex()

@app.route("/confirmReceive", methods=["POST"])
def confirm_receive():
    response = {"response": ""}
    transaction_address = request.json.get("transaction_address")
    api_key = request.headers.get("Authorization")

    if api_key:
        api_key = api_key.replace("Basic ", "", 1)
        try:
            api_key = base64.b64decode(api_key).decode("utf-8")
        except TypeError:
            pass
        userFromSession = app.mongo.db.session.find_one({"session_id": api_key})
        if userFromSession:
            updateTransaction = app.mongo.db.user.find_one_and_update(
                filter={"_id": userFromSession["userId"]},
                update={"$set": {"transaction_list." + str(transaction_address): "received"}}
            )
            buyer_id, seller_id, data, total_amount = get_transaction_info(transaction_address) # TODO 從區塊鏈拿transaction內容
            seller = app.mongo.db.user.find_one({"_id": ObjectId(seller_id)})
            pay_seller(seller['wallet_address'], total_amount) # TODO 需要 total amount (需要從之前的交易爬total amount)
        else:
            response["response"] = "User has not logged in"
            return make_response(json.dumps(response), 400)
            
    else:
        response["response"] = "Authorization error"
        return make_response(json.dumps(response), 400)
    
    return make_response(json.dumps(response,200))

### TODO 
def get_transaction_info(transaction_address):
    w3 = Infura().get_web3()
    input_data = w3.eth.getTransaction(transaction_address)['input']
    input_data_decode = codecs.decode(input_data[2:], 'hex')
    json_data = json.loads(input_data_decode.decode('utf-8'))

    seller_id = json_data['seller']
    buyer_id = json_data['buyer']
    data = json_data['data']
    total_amount = json_data['data']['total']
    return buyer_id, seller_id, data, total_amount

# 由平台錢包轉錢至賣家錢包
def pay_seller(seller_address, total_amount):
    w3 = Infura().get_web3()
    amount_in_ether = total_amount
    amount_in_wei = w3.toWei(amount_in_ether,'ether')

    acct = w3.eth.account.privateKeyToAccount('0x999028f9956d8aab71015b3a0648b3f0a512ce417d91d1e993518e4d23408eda') # 平台錢包的 private key

    txn_dict = {
            'to': user_address, 
            'value': amount_in_wei,
            'gas': 4465030,
            'gasPrice': w3.toWei('21', 'gwei'),
            'from': '0x12CaAe9aAF2bAEdB11471678232ad73bEF5C2889', # 平台錢包的 address
            'nonce': w3.eth.getTransactionCount('0x12CaAe9aAF2bAEdB11471678232ad73bEF5C2889'), # 平台錢包的 address
            'data': buy_list.encode('utf-8')
    }
    
    signed_txn = acct.signTransaction(txn_dict)
    txn_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    txReceipt = w3.eth.waitForTransactionReceipt(txn_hash)
