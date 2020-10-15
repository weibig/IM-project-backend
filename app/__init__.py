from flask import Flask
from flask_pymongo import PyMongo
from flask_login import LoginManager

app = Flask(__name__)

lm = LoginManager()
lm.init_app(app)
app.secret_key = "password"

app.config["MONGO_URI"] = "mongodb://127.0.0.1:27017/test"
app.mongo = PyMongo(app)
app.APP_URL = "http://127.0.0.1:5000"

# Example of how to create index on startup
#
# with app.app_context():
#     print("Setting up indexes:")
#     eventIndex = app.mongo.db.collection.create_index([
#         ('title', "text"),
#     ],
#     name="collection_search_index",
#     weights={
#         'title':100,
#     })

if __name__ == "__main__":
    app.run(debug=True)

from app import user_registration
