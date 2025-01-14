# a few examples on api
###########################################
# login with user: admin, password: admin
# request: curl -X POST -d '{"username":"admin", "password":"admin"}' -H 'Content-Type: application/json'  localhost:5000/login
# resp: {
#   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjAzNDQ1MCwianRpIjoiMzRiOThjZWUtNTg0NS00Y2RjLTg1NGUtZWQzNGVmOTZhNTVlIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMDM0NDUwLCJjc3JmIjoiNjAyNTY0NzktOTBmNC00ZTEyLWJiNjgtMjI1MmUzOTUxMzM2IiwiZXhwIjoxNzMyMDM1MzUwfQ.4Z7qTlnkB2pjTLEHJUKzxdP7BGP8PEOc-YyYu2O24gI"
# }
# ###############################################
# create user: curl -X POST -d '{"username":"user", "password":"password"}' -H 'Content-Type: application/json'  localhost:5000/users
# if responce code 200 then user created, else failed (or user exists), currently there is no logged in user required to create user
#############################################
# request to protected endpoint: curl -X GET -H 'Content-Type: application/json' -H 'Authorization: Bearer <JWT_TOKEN>' localhost:5000/protected 
#curl -X GET -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjAzNDk1NywianRpIjoiMzBkYTA2YWItYTVkYS00NWY0LWIwNGQtNzA1MjdhNDBmM2IwIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMDM0OTU3LCJjc3JmIjoiY2U1ZWY3NmMtNzAwYy00NzczLWI2MzMtOGQ5YjViODhiZTM2IiwiZXhwIjoxNzMyMDM1ODU3fQ.7y19ebVC71AKVQCaB6_G2bH6IBM6__n7FDDiF2OoBlM' localhost:5000/protected
# {
#   "message": "Hello, admin! This is a protected endpoint."
# }

#
# create rent for car - no login requried (for tests)
# curl -X POST -d '{"id":"123123123", "brand":"test", "model":"12123123", "rentalOption":"test"}' -H 'Content-Type: application/json'  localhost:5000/rentals
# return POST:
# {
#   "message": "Rental created successfully"
# }
# return GET
# [
#   {
#     "brand": "test",
#     "id": "123123123",
#     "model": "12123123",
#     "rentalOption": "test"
#   }
# ]
#
# create car  - no login requrired (for tests)
# curl -X POST -d '{"brand":"123123123", "model":"test", "year": 123, "fuel":"gasoline", "pricePerDay": "tooMuchForMe"}' -H 'Content-Type: application/json'  localhost:5000/cars
# return POST:
# {
#   "message": "Car created successfully"
# }
# return GET:
# [
#   {
#     "brand": "123123123",
#     "fuel": "gasoline",
#     "model": "test",
#     "pricePerDay": "tooMuchForMe",
#     "year": 123
#   }
# ]


rentals = list()
cars = list()




from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flasgger import Swagger, swag_from
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'lkasdfuidvbhjwefjbfopiqwejbdfghjkuiopadwejkbwefjkl'  # Replace with a secure key in production
app.config['SWAGGER'] = {
    'title': 'User Management API',
    'uiversion': 3
}
jwt = JWTManager(app)
Swagger(app)

# In-memory user storage (replace with a database in production)
users = {}
users['admin'] = generate_password_hash('admin')

cars = list()

@app.route('/rentals', methods=['POST'])
def create_rental():
    """Endpoint to create a new rental."""
    data = request.get_json()
    if not ('id' in data and 'brand' in data and 'model' in data and 'rentalOption' in data):
        return jsonify({'message': 'Invalid input'}), 400
    rentals.append(data)
    return jsonify({'message': 'Rental created successfully'}), 200

@app.route('/rentals', methods=['GET'])
def get_rentals():
    """Endpoint to retrieve the list of rentals."""
    return jsonify(rentals), 200

@app.route('/cars', methods=['POST'])
def create_car():
    data = request.get_json()
    if not ('brand' in data and 'model' in data and 'year' in data and 'fuel' in data and 'pricePerDay' in data):
        return jsonify({'message': 'Invalid input'}), 400
    cars.append(data)
    return jsonify({'message': 'Car created successfully'}), 200

@app.route('/cars', methods=['GET'])
def get_cars():
    """Endpoint to retrieve the list of cars."""
    return jsonify(cars), 200


@app.route('/users', methods=['POST'])
def create_user():
    """Endpoint to create a new user"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Invalid input'}), 400
    if username in users:
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = generate_password_hash(password)
    users[username] = hashed_password
    return jsonify({'message': 'User created successfully'}), 200

@app.route('/login', methods=['POST'])
def login():
    """Endpoint to login and receive a JWT"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_password = users.get(username)
    if user_password and check_password_hash(user_password, password):
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 400


def protected():
    """Protected endpoint accessible only with a valid JWT"""
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello, {current_user}! This is a protected endpoint.'}), 200

if __name__ == '__main__':
    app.run(debug=True)

