from flask import Flask
from flask_pymongo import PyMongo
from flask_login import LoginManager
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)
lm = LoginManager()
lm.init_app(app)
app.secret_key = "password"  # os.getenv("MONGO_INITDB_ROOT_PASSWORD")


# CONNECTION_STRING = "mongodb+srv://test:test@flask-mongodb-atlas-1g8po.mongodb.net/test?retryWrites=true&w=majority"
# client = pymongo.MongoClient(CONNECTION_STRING)
# db = client.get_database('flask_mongodb_atlas')
# user_collection = pymongo.collection.Collection(db, 'user_collection'


app.config["MONGO_URI"] = "mongodb+srv://weibig:wendy0223@cluster0.dx9k9.mongodb.net/test?retryWrites=true&w=majority"
app.mongo = PyMongo(app)

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
    app.run(debug=True, threaded=True)
from app import views