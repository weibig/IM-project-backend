from werkzeug.security import check_password_hash, generate_password_hash
from app import app
from datetime import datetime
from bson import json_util
from web3 import Web3, HTTPProvider


class User:
    def __init__(self, id):
        self.id = id
        self.username = None
        self.email = None
        self.password_hash = None
        self.wallet_address = None
        self.priv_key = None
        self.buy_transaction = [] # ["time":time, "address":tid, "status":status]
        self.sell_transaction = [] # ["time":time, "address":tid, "status":status]
        self.cart_list = {} # {pid: amount}
        # self.buy_list = {} # {seller: {pid:amount,total:price}}
        self.sell_list = {} # {pid: amount}

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def set_email(self, email):
        self.email = email

    @staticmethod
    def validate_login(password_hash, password):
        return check_password_hash(password_hash, password)

    @staticmethod
    def build_user(user):
        userObj = User(json_util.dumps(user["_id"]))
        userObj.username = user["username"]
        userObj.email = user["email"]
        userObj.password_hash = user["password_hash"]
        userObj.wallet_address = user["wallet_address"]
        userObj.priv_key = user["priv_key"]
        userObj.buy_transaction = user["buy_transaction"]
        userObj.sell_transaction = user["sell_transaction"]
        userObj.cart_list = user["cart_list"]
        # userObj.buy_list = user["buy_list"]
        userObj.sell_list = user["sell_list"]

        return userObj

    def save(self):
        self.id = app.mongo.db.user.insert(
            {
                "username": self.username,
                "password_hash": self.password_hash,
                "email": self.email,
                "createtedAt": datetime.now(),
                "wallet_address": self.wallet_address,
                "priv_key": self.priv_key,
                "buy_transaction": self.buy_transaction,
                "sell_transaction": self.sell_transaction,
                "cart_list": self.cart_list,
                # "buy_list": self.buy_list,
                "sell_list": self.sell_list,
            }
        )
        if self.id:
            return True
        else:
            return False


class Product:
    def __init__(self, id, name, image_urls, description, price):
        self.id = id
        self.name = name
        self.image_urls = image_urls
        self.description = description
        self.price = price
        self.owner = None

    @staticmethod
    def build_product(self, product):
        productObj = Product(json_util.dumps(product["_id"]))
        productObj.name = product["name"]
        productObj.image_urls = product["image_urls"]
        productObj.description = product["description"]
        productObj.price = product["price"]
        productObj.owner = product["owner"]
        return productObj

    def setOwner(self, ownerId):
        self.owner = ownerId

    def save(self):
        self.id = app.mongo.db.product.insert(
            {
                "name": self.name,
                "image_urls": self.image_urls,
                "description": self.description,
                "price": self.price,
                "owner": self.owner,  # userId
            }
        )
        if self.id:
            return True
        else:
            return False

class Infura:

    def __init__(self):
        self.w3 = Web3(HTTPProvider("https://ropsten.infura.io/v3/57caa86e6f454063b13d717be8cc3408"))
        pass

    def get_web3(self):
        if not self.w3.isConnected():
            raise InfuraErrorException()
        return self.w3

class InsufficientFundsException(Exception):
    """
    Raised when user want to send funds and have insufficient balance on address
    """
    pass


class InsufficientERC20FundsException(Exception):
    """
    Raised when user want to send ERC20 contract tokens and have insufficient balance
    of these tokens on wallet's address
    """
    pass


class ERC20NotExistsException(Exception):
    """
    Raised when user want manipulate with token which doesn't exist in wallet.
    """
    pass


class InvalidTransactionNonceException(Exception):
    """
    Raised when duplicated nonce occur or any other problem with nonce
    """
    pass


class InvalidValueException(Exception):
    """
    Raised when some of expected values is not correct.
    """
    pass


class InvalidPasswordException(Exception):
    """
    Raised when invalid password was entered.
    """
    pass


class InfuraErrorException(Exception):
    """
    Raised when wallet cannot connect to infura node.
    """
