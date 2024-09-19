import jwt, datetime, os
from flask import Flask, request
import pymysql
from pymysql.cursors import DictCursor

server = Flask(__name__)

#Create a function to get a database connection
def get_db_connection():
    return pymysql.connect(
        host=os.environ.get("MYSQL_HOST"),
        user=os.environ.get("MYSQL_USER"),
        password=os.environ.get("MYSQL_PASSWORD"),
        database=os.environ.get("MYSQL_DB"),
        port=int(os.environ.get("MYSQL_PORT", 3306)),
        cursorclass=DictCursor
    )

@server.route("/login", methods=["POST"])
def login():
    print("reached auth-login")
    auth = request.authorization
    if not auth:
        return "missing credentials.", 401

    #check db for username and password
    try:
        with get_db_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT email, password FROM user WHERE email=%s", 
                    (auth.username,)
                )
                result = cursor.fetchone()

        if result:
            email = result['email']
            password = result['password']

            if auth.username != email or auth.password != password:
                return "invalid credentials", 401
            else:
                return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)
        else:
            return "invalid credentials", 401

    except pymysql.Error as e:
        print(f"Database error: {e}")
        return "An error occurred", 500

@server.route("/validate", methods=["POST"])
def validate():
    encode_jwt = request.headers["Authorization"]

    if not encode_jwt:
        return "missing credentials.", 401
    
    encode_jwt = encode_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            encode_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
        )
    except:
        return "not authorized", 403
    
    return decoded, 200

def createJWT(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp":datetime.datetime.utcnow() + datetime.timedelta(days=1),
            "iat":datetime.datetime.utcnow(),
            "admin":authz
        },
        secret,
        algorithm="HS256",
    )
if __name__ == "__main__":
    server.run(host="0.0.0.0",port=5000)