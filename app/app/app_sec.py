import bcrypt
import html 
import re
import cherrypy
from jinja2 import Environment, FileSystemLoader
import os
import secrets
import sqlite3 

import jwt
import datetime

from PIL import Image
import hashlib
import requests
import qrcode
import pyotp
import traceback
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


CURRENT_DIR = os.path.dirname(__file__)
SERVER_PATH = os.path.dirname(os.path.abspath(__file__))
SESSION_KEY = 'OnlineShop_Key'

DB = os.path.join(CURRENT_DIR, "database", "online_shop.db")

# Initialize Jinja2 template environment

env = Environment(loader=FileSystemLoader(os.path.join(CURRENT_DIR, 'templates')))

stored_tokens = set()
blacklisted_tokens = set()

SECRET_KEY = 'secret_key'


def generate_jwt(username):
    while True:
        payload = {
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  # Token expiration time
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        if token not in blacklisted_tokens:
            break

    stored_tokens.add(token)
    return token


def verify_token(func):
    def wrapper(*args, **kwargs):
        token = cherrypy.request.headers.get('Authorization')
        if not token:
            raise cherrypy.HTTPError(401, 'Missing token')
        try:
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if token not in stored_tokens:
                raise cherrypy.HTTPError(401, 'Token is not valid')
            if 'exp' in decoded_token:
                current_time = datetime.datetime.utcnow().timestamp()
                if current_time > decoded_token['exp']:
                    blacklisted_tokens.add(token)
                    raise jwt.ExpiredSignatureError('Token has expired')
            return func(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            raise cherrypy.HTTPError(401, 'Token expired')
        except jwt.InvalidTokenError:
            raise cherrypy.HTTPError(401, 'Invalid token')
        except jwt.DecodeError:
            raise cherrypy.HTTPError(401, 'Invalid token')
    return wrapper

def generate_refresh_token(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)  # Refresh token expiration time
    }
    refresh_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return refresh_token

def refresh_jwt(refresh_token):
    try:
        decoded_token = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
        new_token = generate_jwt(decoded_token['username'])
        return new_token
    except jwt.ExpiredSignatureError:
        raise cherrypy.HTTPError(401, 'Refresh token expired')
    except jwt.InvalidTokenError:
        raise cherrypy.HTTPError(401, 'Invalid refresh token')
    except jwt.DecodeError:
        raise cherrypy.HTTPError(401, 'Invalid refresh token')


def add_otp_key(username, otp_key):
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        UPDATE users SET otp_key = ? WHERE username = ?
        ''', (otp_key, username))
        conn.commit()

def get_otp_key(username):
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT otp_key FROM users WHERE username = ?
        ''', [username])
        query_result = cursor.fetchone()
        if query_result:
            return query_result[0]
        else:
            return None

def generate_otp(username):
    key = pyotp.random_base32()
    uri = pyotp.totp.TOTP(key).provisioning_uri(username, issuer_name="OnlineShop")
    img = qrcode.make(uri)
    img_file_path = os.path.join(os.path.dirname(__file__), f"static/images/otp/{username}_totp.png")
    img.save(img_file_path)
    img_url_path = f"/static/images/otp/{username}_totp.png"
    return key, img_url_path

def generate_csrf_token(self):
        csrf_token = secrets.token_urlsafe(16)
        cherrypy.session['csrf_token'] = csrf_token
        return csrf_token

def error_handler(status, message, traceback, version):
    tmpl = env.get_template('error_page.html')
    return tmpl.render(status_code=status)

def IsLogged() -> bool:
    return cherrypy.session.get('logged_in')

def IsAdmin(username) -> bool:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("select * from users where username= ? and role=1", [username])
        query_result = cursor.fetchone()
        if query_result:
            return True
    conn.close()

    return False

def save_picture(picture) -> str:
    random_hex = secrets.token_hex(8)
    _, file_ext = os.path.splitext(picture.filename)
    picture_fn = random_hex + file_ext
    picture_path = os.path.join(
        CURRENT_DIR, 'static/images/profile', picture_fn)

    # get the original width and height of the image
    image = Image.open(picture.file)
    original_width, original_height = image.size

    # calculate the aspect ratio of the image
    aspect_ratio = original_width / original_height

    # set the new height to 512, and calculate the new width based on the aspect ratio
    new_height = 512
    new_width = round(new_height * aspect_ratio)

    # resize the image using the calculated width and height
    resized_image = image.resize((new_width, new_height))

    # create a new blank image with a size of 512x512
    new_image = Image.new("RGB", (512, 512))

    # calculate the coordinates to paste the resized image onto the new image
    x_offset = round((512 - new_width) / 2)
    y_offset = round((512 - new_height) / 2)

    # paste the resized image onto the new image
    new_image.paste(resized_image, (x_offset, y_offset))
    new_image.save(picture_path)

    return picture_fn 

def IsUser(username, email=None, password=None) -> bool:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        if email is not None and password is None:
            cursor.execute("SELECT username, email FROM users WHERE username = ? OR email = ?", [username, email])
            query_result = cursor.fetchone()
            if query_result:
                return True

        elif password is not None and email is None:
            cursor.execute("SELECT password FROM users WHERE username = ?", [username])
            hashed_password = cursor.fetchone()

            if hashed_password: 
                hashed_password = hashed_password[0]

                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    return True

    conn.close()
    return False 

def addUser(username, email, password) -> None:
    default_pic = "/static/images/profile/default.jpg"
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users(username, email, password, role, profile_url) VALUES (?,?,?,?,?)",
                       [username, email, hashed_password, False, default_pic])
        conn.commit()
    conn.close()

    return None

def retrieveGenericProducts() -> []:
    home_products = []

    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        for table in ["home_stock", "book_stock"]:
            cursor.execute(f'''
                SELECT 
                    products.id, 
                    products.name, 
                    products.description, 
                    products.price, 
                    products.category, 
                    products.image_url, 
                    {table}.stock 
                FROM 
                    products 
                JOIN 
                    {table} ON products.id = {table}.product_id
            ''')
            query_result = cursor.fetchall() 

            for row in query_result:
                product = {
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "price": row[3],
                    "category": row[4],
                    "image": row[5],
                    "stock": row[6]
                }
                home_products.append(product)
    conn.close()

    return home_products 

def retrieveClothingProducts() -> []:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                products.id, 
                products.name, 
                products.description, 
                products.price, 
                products.category, 
                products.image_url, 
                clothing_stock.size, 
                clothing_stock.stock 
            FROM 
                products 
            JOIN 
                clothing_stock ON products.id = clothing_stock.product_id
        ''')
        query_result = cursor.fetchall() 

        product_data = {}
        for row in query_result:
            product_id = row[0]
            size = row[6]
            stock = row[7]

            if product_id not in product_data:
                product_data[product_id] = {
                    'id': product_id,
                    'name': row[1],
                    'description': row[2],
                    'price': row[3],
                    'category': row[4],
                    'image': row[5],
                    'stock': [(size, stock)]
                }
            else:
                product_data[product_id]['stock'].append((size, stock))
    conn.close()

    return list(product_data.values())

def addToCart(product_id, username, size=None) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username=?", [username])
        user_id = cursor.fetchone()[0]

        if size is not None:
            cursor.execute('''SELECT 
                            quantity 
                            FROM 
                            shopping_cart WHERE product_id=? AND user_id=? AND size=?
                            ''', [product_id, user_id, size])

            existing_quantity = cursor.fetchone()
            if existing_quantity and existing_quantity[0] > 0:
                cursor.execute('''UPDATE 
                                shopping_cart 
                                SET quantity=? 
                                WHERE user_id=? AND product_id=? AND size=?
                                ''', [existing_quantity[0] + 1, user_id, product_id, size])
            else:
                cursor.execute('''INSERT INTO 
                               shopping_cart (user_id, product_id, quantity, size) 
                               VALUES (?,?,?,?)
                               ''', [user_id, product_id, 1, size])
        else:
            cursor.execute('''SELECT 
                            quantity 
                            FROM 
                            shopping_cart WHERE product_id=? AND user_id=?
                            ''', [product_id, user_id])

            existing_quantity = cursor.fetchone()

            if existing_quantity and existing_quantity[0] > 0:
                cursor.execute('''UPDATE 
                                shopping_cart 
                                SET quantity=? WHERE user_id=? AND product_id=?
                                ''', [existing_quantity[0] + 1, user_id, product_id])
            else:
                cursor.execute('''INSERT INTO 
                               shopping_cart (user_id, product_id, quantity) 
                               VALUES (?,?,?)
                               ''', [user_id, product_id, 1])
        conn.commit()
    conn.close()

    return None

def removeReview(product_id, username) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM reviews WHERE product_id=? AND user_id=(SELECT id FROM users WHERE username=?)",
                       [product_id, username])
        conn.commit()
    conn.close()

    return None

def addReview(product_id, username, rate, review) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reviews WHERE product_id=? AND user_id=(SELECT id FROM users WHERE username=?)",
                       [product_id, username])

        existing_review = cursor.fetchone()

        if existing_review:
            cursor.execute("UPDATE reviews SET rating=?, comment=? WHERE user_id=(SELECT id FROM users WHERE username=?) AND product_id=?",
                           [rate, review, username, product_id])
        else:
            cursor.execute("INSERT INTO reviews (user_id, product_id, rating, comment) VALUES ((SELECT id FROM users WHERE username=?),?,?,?)",
                           [username, product_id, rate, review])
        conn.commit()
    conn.close()

    return None

def getUser(username) -> {}:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, profile_url, role FROM users WHERE username=?", [username])
        query_result = cursor.fetchone() 

        if query_result:
            user = {
                "id": query_result[0],
                "username": query_result[1],
                "email": query_result[2],
                "picture": query_result[3],
                "role": query_result[4]
            }
            return user 
    conn.close()

    return {} 

def getAvgRating(id) -> int:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT AVG(rating) FROM reviews WHERE product_id=?", [id])
        query_result = cursor.fetchone() 
    conn.close()

    return query_result[0]

def getReviews(id) -> []:
    reviews = []
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT 
                        users.username,
                        reviews.rating,
                        reviews.comment  
                        FROM 
                        reviews 
                        JOIN 
                        users ON reviews.user_id=users.id 
                        WHERE reviews.product_id=?
                       ''', [id])
        query_result = cursor.fetchall() 

        if query_result:
            for row in query_result:
                review = {
                    "user": row[0],
                    "rating": row[1],
                    "review": row[2]
                }
                reviews.append(review)
    conn.close()

    return reviews 

def getProduct(id) -> {}:
    product = {}

    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                products.id, 
                products.category, 
                products.name, 
                products.price, 
                products.image_url, 
                products.description, 
                clothing_stock.size, 
                clothing_stock.stock 
            FROM 
                products 
            JOIN 
                clothing_stock ON products.id = clothing_stock.product_id
            WHERE 
                products.id = ?
        ''', [id])
        query_result = cursor.fetchall() 

        if query_result:
            product = {
                "id": query_result[0][0],
                "category": query_result[0][1],
                "name": query_result[0][2],
                "price": query_result[0][3],
                "image": query_result[0][4],
                "description": query_result[0][5],
                "stock": [(row[6], row[7]) for row in query_result]
            }

        for table in ["home_stock", "book_stock"]:
            cursor.execute(f'''
                SELECT 
                    products.id, 
                    products.category, 
                    products.name, 
                    products.price, 
                    products.image_url, 
                    products.description, 
                    {table}.stock 
                FROM 
                    products 
                JOIN 
                    {table} ON products.id = {table}.product_id
                WHERE 
                    products.id = ?
            ''', [id])
            query_result = cursor.fetchone() 

            if query_result:
                product = {
                    "id": query_result[0],
                    "category": query_result[1],
                    "name": query_result[2],
                    "price": query_result[3],
                    "image": query_result[4],
                    "description": query_result[5],
                    "stock": query_result[6]
                }
    conn.close()

    return product

def setPicUrl(img_path, username) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT profile_url FROM users WHERE username=?", [username])
        old_img_path = cursor.fetchone()[0]
        img_name = os.path.basename(old_img_path)

        if img_name != "default.jpg":
            old_img_path = os.path.join(CURRENT_DIR, "static/images/profile", img_name)

            try:
                os.remove(old_img_path)
            except FileNotFoundError:
                print(f"{old_img_path} doesn't exist.")

        path = "/static/images/profile" + img_path
        cursor.execute("UPDATE users SET profile_url=? WHERE username=?", [path, username])
        conn.commit()
    conn.close()
    return None

def IsReviewed(id, user_id) -> bool:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reviews WHERE product_id=? AND user_id=?", [id, user_id])
        query_result = cursor.fetchone()

        if query_result:
            return True
    conn.close()

    return False 

def calculateCartPrice(username) -> (int, []):
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                shopping_cart.cart_id, 
                users.id, 
                products.id, 
                products.price, 
                shopping_cart.quantity,
                shopping_cart.size,
                products.name
            FROM 
                shopping_cart 
            JOIN 
                users ON shopping_cart.user_id = users.id 
            JOIN 
                products ON shopping_cart.product_id = products.id
            WHERE 
                users.username=?
        ''', [username])
        cart_items = cursor.fetchall()

        total_price = 0
        products_in_cart = []

        for item in cart_items:
            total_price += item[3] * item[4]
            products_in_cart.append({
                'id': item[0],
                'user_id': item[1],
                'product_id': item[2],
                'price': item[3],
                'quantity': item[4],
                'size': item[5],
                'name': item[6],
            })
    conn.close()

    return total_price, products_in_cart

def removeFromCart(cart_id, username, size) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()

        if size == 'None':
            cursor.execute('''
                DELETE FROM shopping_cart
                WHERE 
                    cart_id = ? AND
                    user_id = (SELECT id FROM users WHERE username = ?)
            ''', (cart_id, username))
        else:
            cursor.execute('''
                DELETE FROM shopping_cart
                WHERE 
                    cart_id = ? AND size=? AND
                    user_id = (SELECT id FROM users WHERE username = ?)
            ''', [cart_id, size, username])

        conn.commit()
    conn.close()

    return None

def updateCartItemQuant(cart_id, value, username) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE shopping_cart
            SET quantity = ?
            WHERE
                cart_id = ? AND
                user_id = (SELECT id FROM users WHERE username = ?)

        ''', [value, cart_id, username])
        conn.commit()
    conn.close()

    return None

def changePassword(username, password) -> None:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users
            SET password = ?
            WHERE 
                username = ?
        ''', [hashed_password, username])

        conn.commit()
    conn.close()

    return None

def getCartItems(username) -> []:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM shopping_cart
            WHERE
                user_id = (SELECT id FROM users WHERE username = ?)
        ''', [username])
        cart = cursor.fetchall()
    conn.close()

    return cart

def decrementStock(product_id, quantity, size) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT category FROM products
            WHERE
                id = ?
        ''', [product_id])
        category = cursor.fetchone()[0]
        if category == "Home":
            table = "home_stock"
        elif category == "Clothing":
            table = "clothing_stock"
        else:
            table = "book_stock"
        if not size:
            cursor.execute(f'''
                UPDATE {table}
                SET stock = CASE
                    WHEN stock >= ? THEN stock - ?
                    ELSE stock
                END
                WHERE 
                    product_id = ?     
            ''', [quantity, quantity, product_id])
        else:
            cursor.execute(f'''
                UPDATE {table}
                SET stock = CASE
                    WHEN stock >= ? THEN stock - ?
                    ELSE stock
                END
                WHERE 
                    product_id = ? AND
                    size = ?
            ''', [quantity, quantity, product_id, size])
    conn.close()

    return None

def resetCart(username) -> None:
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM shopping_cart 
            WHERE
                user_id = (SELECT id FROM users WHERE username = ?)
        ''', [username])
        conn.commit()
    conn.close()

    return None


def is_password_valid(password):
    # Check password length
    if len(password) < 12:
        return "Password should be at least 12 characters long"
    if len(password) > 128:
        return "Password can't exceed 128 characters" 

    # Kanji and Emojis Unicodes
    emoji_pattern = re.compile(r'[\U0001F300-\U0001F5FF\U0001F600-\U0001F64F]')  # Emoji Unicode range
    n_emojis = len(re.findall(emoji_pattern, password))
    if n_emojis > 12:
        return "Password can not contain more than 12 emojis"

    kanji_pattern = re.compile(r'[\u4E00-\u9FFF]')  # Kanji Unicode range
    n_kanji = len(re.findall(kanji_pattern, password))
    if n_kanji > 64:
        return "Password can not contain more than 64 kanji characters"

    if is_password_breached(password):
        return "Password is breached. Please choose a different one"

    return None

def is_password_breached(password):
    # Hash the password using SHA-1 hashing algorithm
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()  # Convert to uppercase

    # Split the hashed password prefix and suffix
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    # Send the prefix to the HIBP API to check for breaches (k-anonymity)
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    # Check if the suffix (remainder of the hashed password) is in the response
    breached_suffixes = [line.split(':')[0] for line in response.text.splitlines()]
    if suffix in breached_suffixes:
        return True

    return False

class ChangePassword(object):
    @cherrypy.expose
    def index(self, current_password, new_password, confirm_password):
        current_password = html.escape(current_password)
        new_password = html.escape(new_password)
        confirm_password = html.escape(confirm_password)

        if IsLogged() and cherrypy.request.method == 'POST':
            username = cherrypy.session.get('username')
            if IsUser(username=username, password=current_password) and new_password == confirm_password:
                if(is_password_breached(new_password)):
                    tmpl = env.get_template('user/profile.html')
                    user = getUser(username)
                    return tmpl.render(user=user, IsLogged=IsLogged(), error='Password is breached. Please choose a different one')
                changePassword(username, new_password)
        raise cherrypy.HTTPRedirect("/profile")


class UpdateProfilePic(object):
    @cherrypy.expose
    def index(self, profile_picture=None):
        tmpl = env.get_template('user/profile.html')
        username = cherrypy.session.get('username')
        user = getUser(username)
        if profile_picture and profile_picture.filename and IsLogged():
            allowed_extensions = {'.png', '.jpg', '.jpeg'}
            _, file_ext = os.path.splitext(profile_picture.filename)

            if file_ext.lower() not in allowed_extensions:
                error_message = "Invalid file extension. Please upload a .png, .jpg, or .jpeg file."
                return tmpl.render(user=user, IsLogged=IsLogged(), upload_error=error_message)

            max_file_size = 1 * 500 * 1024 
            if len(profile_picture.file.read()) > max_file_size:
                error_message = "File size exceeds the limit (500 kb). Please upload a smaller file."
                return tmpl.render(user=user, IsLogged=IsLogged(), upload_error=error_message)

            # reset fp after reading
            profile_picture.file.seek(0)

            # save the image
            img_name = save_picture(profile_picture)
            setPicUrl("/" + img_name, cherrypy.session.get('username'))
            raise cherrypy.HTTPRedirect("/profile")

        error_message = "Error uploading image. Please make sure to select a valid image file."
        return tmpl.render(user=user, IsLogged=IsLogged(), upload_error=error_message)

class Profile(object):
    def __init__(self):
        self.change_password = ChangePassword()
        self.upload_pic = UpdateProfilePic()

    @cherrypy.expose
    def index(self):
        tmpl = env.get_template('user/profile.html')
        user = getUser(cherrypy.session.get('username'))

        if IsLogged():
            tmpl = env.get_template('user/profile.html')
            return tmpl.render(user=user, IsLogged=IsLogged())
        else:
            raise cherrypy.HTTPRedirect("/login")

        return tmpl.render(IsLogged=IsLogged())


class Confirmation(object):
    @cherrypy.expose
    def index(self):
        if not IsLogged():
            raise cherrypy.HTTPRedirect("/login")

        resetCart(cherrypy.session.get('username'))
        tmpl = env.get_template('cart/order_confirmation.html')
        return tmpl.render(IsLogged=IsLogged())


class UpdateItemsInStock(object):
    @cherrypy.expose
    def index(self, payment_method, billing_address, shipping_address):
        payment_method = html.escape(payment_method)
        billing_address = html.escape(billing_address)
        shipping_address = html.escape(shipping_address)

        if cherrypy.request.method == 'POST':
            if not IsLogged():
                raise cherrypy.HTTPRedirect("/login")

            cart_items = getCartItems(cherrypy.session.get('username'))
            for item in cart_items:
                product_id = item[2]
                quantity = item[3]
                size = item[4]
                decrementStock(product_id, quantity, size)

            raise cherrypy.HTTPRedirect('/cart/checkout/confirmation')

class Checkout(object):
    def __init__(self):
        self.confirmation = Confirmation()
        self.update_cart_items = UpdateItemsInStock()

    @cherrypy.expose
    def index(self):
        if not IsLogged():
            raise cherrypy.HTTPRedirect("/login")

        tmpl = env.get_template('cart/checkout.html')
        return tmpl.render(IsLogged=IsLogged())


class Cart(object):
    def __init__(self):
        self.checkout = Checkout()

    @cherrypy.expose
    def index(self):
        tmpl = env.get_template('cart/view_cart.html')
        if(IsLogged()):
            cart_price, products_in_cart = calculateCartPrice(cherrypy.session.get('username'))
            return tmpl.render(IsLogged = True, products_in_cart=products_in_cart, total_price=round(cart_price,2))
        return tmpl.render(IsLogged = False, products_in_cart=[], total_price=0)

    @cherrypy.expose
    def remove_item(self, id, size=None):
        id = html.escape(id)

        if size is not None:
            size = html.escape(size)

        if cherrypy.request.method == 'POST':
            if IsLogged():
                removeFromCart(id, cherrypy.session.get('username'), size)
        raise cherrypy.HTTPRedirect("/cart")

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST', 'PUT'])
    def update_item(self, cart_id, value):
        cart_id = html.escape(cart_id)
        value = html.escape(value)

        if cherrypy.request.method == 'PUT':
            updateCartItemQuant(cart_id, value, cherrypy.session.get('username'))

class Product(object):
    @cherrypy.expose
    def index(self, id):
        id = html.escape(id)

        tmpl = env.get_template('product/details.html')
        product = getProduct(id)
        avg_rating = getAvgRating(id)
        item_reviews = getReviews(id)

        if avg_rating is None:
            avg_rating = 0

        if IsLogged():
            user = getUser(cherrypy.session['username'])
            if item_reviews and IsReviewed(id, user['id']):
                return tmpl.render(product=product, item_reviews=item_reviews, avg_rating=avg_rating, user=user['username'], has_reviewed=True, IsLogged=True)
            return tmpl.render(product=product, item_reviews=item_reviews, avg_rating=avg_rating, user=user['username'], has_reviewed=False, IsLogged=True)

        return tmpl.render(product=product, item_reviews=item_reviews, avg_rating=avg_rating, user=None, has_reviewed=True, IsLogged=False)

    @cherrypy.expose
    def add_review(self, id, rating, review):
        id = html.escape(id)
        rating = html.escape(rating)
        review = html.escape(review)

        if IsLogged():
            addReview(product_id=id, username=cherrypy.session.get('username'), rate=rating, review=review)
            raise cherrypy.HTTPRedirect(f'/shop/product/?id={id}')
        raise cherrypy.HTTPRedirect(f'/shop/product/?id={id}')

    @cherrypy.expose
    def delete_review(self, id, user):
        id = html.escape(id)
        user = html.escape(user)

        removeReview(id, username=user)
        raise cherrypy.HTTPRedirect(f'/shop/product/?id={id}')

    @cherrypy.expose
    def add_to_cart(self, id, size=None):
        id = html.escape(id)

        if size is not None:
            size = html.escape(size)

        if cherrypy.request.method == 'POST':
            if IsLogged(): 
                addToCart(id, cherrypy.session.get('username'), size)

            raise cherrypy.HTTPRedirect(f"/shop/product?id={id}")


class Shop(object):
    def __init__(self):
        self.product = Product()

    @cherrypy.expose
    def index(self):
        tmpl = env.get_template('product/products.html')
        products = retrieveGenericProducts() + retrieveClothingProducts()
        return tmpl.render(products=products, IsLogged=IsLogged())

    @cherrypy.expose
    def search(self, query=None):
        if query is not None:
            query = html.escape(query)

        if query:
            products = retrieveClothingProducts() + retrieveGenericProducts()
            pattern = '.*' + '.*'.join(query.lower()) + '.*'
            search_results = []

            for product in products:
                if re.match(pattern, product['name'].lower()):
                    search_results.append(product)

            tmpl = env.get_template('product/products.html')
            return tmpl.render(products=search_results, query=query, IsLogged=IsLogged())
        raise cherrypy.HTTPRedirect("/shop")


class OnlineShop(object):
    def __init__(self):
        self.cart = Cart()
        self.product = Product()
        self.shop = Shop()
        self.profile = Profile()

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect("/shop")

    @cherrypy.expose
    def login(self, username=None, password=None):
        if username is not None:
            username = html.escape(username)

        if password is not None:
            password = html.escape(password)

        if cherrypy.request.method == 'POST':
            if IsUser(username=username, password=password):
                cherrypy.session.regenerate()
                cherrypy.session['username'] = username
                cherrypy.session['auth_level'] = 1
                raise cherrypy.HTTPRedirect(f"/verify_two_factor_auth?username={username}")
            else:
                tmpl = env.get_template('user/login.html')
                return tmpl.render(error="Invalid username or password.")
        tmpl = env.get_template('user/login.html')
        return tmpl.render()

    @cherrypy.expose
    def verify_two_factor_auth(self, username=None, otp_code=None):
        if not cherrypy.session.get('username'):
            raise cherrypy.HTTPRedirect("/login")

        if not cherrypy.session.get('auth_level'):
            raise cherrypy.HTTPRedirect("/login")

        if cherrypy.request.method == 'POST':
            if cherrypy.session.get('auth_level') != 1 or cherrypy.session.get('username') != username:
                raise cherrypy.HTTPRedirect("/login")

            otp_key = get_otp_key(username)
            totp = pyotp.TOTP(otp_key)
            error = None
            if otp_code:
                if totp.verify(otp_code):
                    cherrypy.session['username'] = username
                    cherrypy.session['logged_in'] = True
                    raise cherrypy.HTTPRedirect("/")
                else:
                    error = "Invalid OTP code."
            tmpl = env.get_template('user/two_factor_auth.html')
            return tmpl.render(username=username, error=error)

        tmpl = env.get_template('user/two_factor_auth.html')
        return tmpl.render(username=username)

    @cherrypy.expose
    def register(self, username=None, email=None, password=None):
        try:
            if cherrypy.request.method == 'POST':
                if username is not None:
                    username = html.escape(username)    

                if email is not None:
                    email = html.escape(email)  

                if password is not None:
                    error_message = is_password_valid(password)

                    if error_message is not None:
                        # Return an error message or redirect to the registration page with an error message
                        tmpl = env.get_template('user/register.html')
                        return tmpl.render(IsLogged=IsLogged(), error=error_message)

                        password = html.escape(password)
                
                cherrypy.session['temp_username'] = username
                cherrypy.session['temp_password'] = password
                cherrypy.session['temp_email'] = email
    
                if not IsUser(username=username, email=email): 
                    otp_key, img_path = generate_otp(username)
                    cherrypy.session['temp_otp_key'] = otp_key
                    cherrypy.session['temp_path'] = img_path
                    tmpl = env.get_template('user/otp_register.html')
                    return tmpl.render(img_path=img_path)
                else:
                    tmpl = env.get_template('user/register.html')
                    return tmpl.render(IsLogged=IsLogged()) 

            if cherrypy.request.method == 'GET':
                tmpl = env.get_template('user/register.html')
                return tmpl.render(IsLogged=IsLogged())

        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

    @cherrypy.expose
    def verify_registration(self, otp_code=None):
        if cherrypy.request.method == 'POST':
            if otp_code:
                otp_key = cherrypy.session.get('temp_otp_key')
                totp = pyotp.TOTP(otp_key)
                if totp.verify(otp_code):
                    addUser(cherrypy.session.get('temp_username'), cherrypy.session.get('temp_email'), cherrypy.session.get('temp_password'))
                    add_otp_key(cherrypy.session.get('temp_username'), cherrypy.session.get('temp_otp_key'))
                    raise cherrypy.HTTPRedirect("/login")
                else:
                    tmpl = env.get_template('user/otp_register.html')
                    return tmpl.render(error="Invalid OTP code.", img_path=cherrypy.session.get('temp_path'))
    # Admin routes
    @cherrypy.expose
    def manage_stock(self):
        tmpl = env.get_template('admin/manage_products.html')
        products = retrieveGenericProducts() + retrieveClothingProducts()
        return tmpl.render(products=products, IsLogged=IsLogged())

    @cherrypy.expose
    def manage_orders(self):
        tmpl = env.get_template('admin/manage_orders.html')
        return tmpl.render()

    @cherrypy.expose
    def logout(self, token=None):
        blacklisted_tokens.add(token)
        if IsLogged():
            cherrypy.session.clear()
            cherrypy.session.delete()
        raise cherrypy.HTTPRedirect("/login")



# Define a custom session class extending CherryPy's session handling
class CustomSession(cherrypy.lib.sessions.RamSession):
    def __init__(self, id=None, **kwargs):
        self.key = get_random_bytes(16)  # Additional line for initializing self.key
        cherrypy.lib.sessions.Session.__init__(self, id=id, **kwargs)  # Call Session (Tree Parent) __init__ method

    def generate_id(self):
        # Customize the session ID generation process here
        random_bytes = secrets.token_bytes(16)
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, _ = cipher.encrypt_and_digest(random_bytes)
        return ciphertext.hex()
    
cherrypy.lib.sessions.RamSession = CustomSession

error_codes = [
    400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 
    411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 
    424, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 
    505, 506, 507, 508, 510, 511
]

cherrypy.config.update({
    f'error_page.{code}': error_handler for code in error_codes
})

# CherryPy configuration for embedding in a WSGI server
cherrypy.server.unsubscribe()
cherrypy.engine.signals.subscribe()
cherrypy.config.update({
    'tools.sessions.storage_class': CustomSession,
    'engine.autoreload.on': False,
    'tools.sessions.on': True,
    'tools.proxy.on': True,
    'tools.sessions.secure': True,
    'tools.sessions.httponly': True,
    'environment': 'embedded',
    'tools.sessions.timeout': 30*24*60, # Minutes
    'tools.sessions.samesite': "Lax"
})

cherrypy.config.update({
    'tools.response_headers.on': True,
    'tools.response_headers.headers': [
        ('Cache-Control', 'no-cache, no-store, must-revalidate'),
        ('Pragma', 'no-cache'),
        ('Expires', '0')
    ]
})

# gunicorn callable
def application(environ, start_response):

    config = {
        "/": {
            'tools.staticdir.root': SERVER_PATH, 
        },
        '/static/css': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static/css/',
        },
        '/static/images': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static/images/',
        },
        '/static/js': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static/js/',
        },
        'static/images/otp': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static/images/otp/',
        },
    }

    cherrypy.tree.mount(OnlineShop(), '/', config=config)
    return cherrypy.tree(environ, start_response)


if __name__ == '__main__':
    cherrypy.engine.start()
    cherrypy.engine.block()
    cherrypy.engine.stop()
