from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
import jwt
import datetime
from bson import ObjectId
from functools import wraps

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb+srv://flask_db:flask_db@flasktest.foy382l.mongodb.net/flask_db?retryWrites=true&w=majority"
mongo = PyMongo(app)
app.config["SECRET_KEY"] = "EZXUK7oc6IePNdWH"


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split()[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = mongo.db.users.find_one({"_id": ObjectId(data["user_id"])})
        except:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data or not all(key in data for key in ["first_name", "last_name", "email", "password"]):
        return jsonify({"message": "Invalid input data"}), 400

    user = {
        "first_name": data["first_name"],
        "last_name": data["last_name"],
        "email": data["email"],
        "password": data["password"],
    }

    existing_user = mongo.db.users.find_one({"email": data["email"]})
    if existing_user:
        return jsonify({"message": "User with this email already exists"}), 409

    mongo.db.users.insert_one(user)

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or not all(key in data for key in ["email", "password"]):
        return jsonify({"message": "Invalid input data"}), 400

    user = mongo.db.users.find_one({"email": data["email"]})
    if not user or user["password"] != data["password"]:
        return jsonify({"message": "Invalid credentials"}), 401

    token = jwt.encode(
        {"user_id": str(user["_id"]), "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return jsonify({"token": token}), 200


@app.route("/template", methods=["POST"])
@token_required
def insert_template(current_user):
    data = request.get_json()

    if not data or not all(key in data for key in ["template_name", "subject", "body"]):
        return jsonify({"message": "Invalid input data"}), 400

    template = {
        "user_id": current_user["_id"],
        "template_name": data["template_name"],
        "subject": data["subject"],
        "body": data["body"],
    }

    mongo.db.templates.insert_one(template)

    return jsonify({"message": "Template inserted successfully"}), 201


@app.route("/template", methods=["GET"])
@token_required
def get_all_templates(current_user):
    templates = mongo.db.templates.find({"user_id": current_user["_id"]})

    result = []
    for template in templates:
        template["_id"] = str(template["_id"])
        result.append(template)

    return jsonify(result), 200


@app.route("/template/<template_id>", methods=["GET"])
@token_required
def get_template(current_user, template_id):
    template = mongo.db.templates.find_one(
        {"_id": ObjectId(template_id), "user_id": current_user["_id"]}
    )

    if not template:
        return jsonify({"message": "Template not found"}), 404

    template["_id"] = str(template["_id"])

    return jsonify(template), 200


@app.route("/template/<template_id>", methods=["PUT"])
@token_required
def update_template(current_user, template_id):
    data = request.get_json()

    if not data or not all(key in data for key in ["template_name", "subject", "body"]):
        return jsonify({"message": "Invalid input data"}), 400

    updated_template = {
        "user_id": current_user["_id"],
        "template_name": data["template_name"],
        "subject": data["subject"],
        "body": data["body"],
    }

    result = mongo.db.templates.update_one(
        {"_id": ObjectId(template_id), "user_id": current_user["_id"]},
        {"$set": updated_template},
    )

    if result.modified_count == 0:
        return jsonify({"message": "Template not found or you don't have permission to update"}), 404

    return jsonify({"message": "Template updated successfully"}), 200


@app.route("/template/<template_id>", methods=["DELETE"])
@token_required
def delete_template(current_user, template_id):
    result = mongo.db.templates.delete_one({"_id": ObjectId(template_id), "user_id": current_user["_id"]})

    if result.deleted_count == 0:
        return jsonify({"message": "Template not found or you don't have permission to delete"}), 404

    return jsonify({"message": "Template deleted successfully"}), 200


if __name__ == "__main__":
   app.run(host="0.0.0.0", port=5000)
