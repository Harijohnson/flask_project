from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
import jwt
import datetime
from bson import ObjectId
from functools import wraps


app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb+srv://flask_db:flask_db @flasktest.foy382l.mongodb.net/flask_db?retryWrites=true&w=majority"
mongo = PyMongo(app)
app.config["SECRET_KEY"] = "harijohnson321"


def token_required(f):
    @wraps(f)
    def decorated(bson='507f191e810c19729de860ea', *args, **kwargs):
        token = None

        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split()[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = mongo.db.users.find_one({"_id": bson.ObjectId(data["user_id"])})
        except:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"message": "No input data provided"}), 400

    user = {
        "first_name": data["first_name"],
        "last_name": data["last_name"],
        "email": data["email"],
        "password": data["password"],
    }

    mongo.db.users.insert_one(user)

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({"message": "Could not verify"}), 401

    user = mongo.db.users.find_one({"email": auth.username})

    if not user:
        return jsonify({"message": "User not found"}), 401

    if user["password"] == auth.password:
        token = jwt.encode(
            {
                "user_id": str(user["_id"]),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )

        return jsonify({"token": token}), 200

    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/template", methods=["POST"])
@token_required
def insert_template(current_user):
    data = request.get_json()

    if not data:
        return jsonify({"message": "No input data provided"}), 400

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
        {"_id": bson.ObjectId(template_id), "user_id": current_user["_id"]}
    )

    if not template:
        return jsonify({"message": "Template not found"}), 404

    template["_id"] = str(template["_id"])

    return jsonify(template), 200


@app.route("/template/<template_id>", methods=["PUT"])
@token_required
def update_template(current_user, template_id):
    data = request.get_json()

    if not data:
        return jsonify({"message": "No input data provided"}), 400

    updated_template = {
        "user_id": current_user["_id"],
        "template_name": data["template_name"],
        "subject": data["subject"],
        "body": data["body"],
    }

    mongo.db.templates.update_one(
        {"_id": bson.ObjectId(template_id), "user_id": current_user["_id"]},
        {"$set": updated_template},
    )

    return jsonify({"message": "Template updated successfully"}), 200


@app.route("/template/<template_id>", methods=["DELETE"])
@token_required
def delete_template(current_user, template_id):
    result = mongo.db.templates.delete_one(
        {"_id": bson.ObjectId(template_id), "user_id": current_user["_id"]}
    )

    if result.deleted_count == 1:
        return jsonify({"message": "Template deleted successfully"}), 200

    return jsonify({"message": "Template not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
