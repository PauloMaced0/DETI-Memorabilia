import sqlite3
import os
import sys

db_directory = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(db_directory, "online_shop.db")

def setup():
    try:
        with sqlite3.connect(DB) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    price REAL NOT NULL,
                    category TEXT NOT NULL,
                    image_url TEXT NOT NULL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clothing_stock(
                    id INTEGER PRIMARY KEY,
                    product_id INTEGER NOT NULL,
                    size TEXT NOT NULL,
                    stock INTEGER NOT NULL,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS home_stock(
                    id INTEGER PRIMARY KEY,
                    product_id INTEGER NOT NULL,
                    stock INTEGER NOT NULL,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS book_stock(
                    id INTEGER PRIMARY KEY,
                    product_id INTEGER NOT NULL,
                    stock INTEGER NOT NULL,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    role BOOLEAN NOT NULL,
                    profile_url TEXT NOT NULL,
                    otp_key TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS orders (
                    order_id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    order_date DATE,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS order_items (
                    item_id INTEGER PRIMARY KEY,
                    order_id INTEGER NOT NULL,
                    user_id INTERGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    quantity INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reviews (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    rating INTEGER NOT NULL,
                    comment TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE shopping_cart (
                cart_id INTEGER PRIMARY KEY,
                user_id INTEGER,
                product_id INTEGER,
                quantity INTEGER,
                size TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (product_id) REFERENCES products(product_id)
                )
            ''')

            #Populate database

            cursor.execute('''
                INSERT INTO users (username, email, password, role, profile_url)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', 'admin@admin.com', '!:QWbwm90?#.x1~', 1, '/static/images/profile/default.jpg'))

            cursor.execute('''
                INSERT INTO products (name, description, price, category, image_url)
                VALUES (?, ?, ?, ?, ?)
            ''', ('Mug', 'Start your day right with our Premium Ceramic Coffee Mug. Crafted from high-quality ceramic, this mug combines durability with a sleek, modern design',
                  10.99, 'Home', '/static/images/products/mug.jpeg'))


            cursor.execute('''
                INSERT INTO products (name, description, price, category, image_url)
                VALUES (?, ?, ?, ?, ?)
            ''', ('T-shirt', 'Elevate your everyday style with our Classi c Cotton Crewneck Shirt. Crafted from premium combed cotton, this shirt offers a comfortable and breathable fit, making it an essential addition to your wardrobe',
                  19.99, 'Clothing', '/static/images/products/shirt3.jpeg'))

            cursor.execute('''
                INSERT INTO products (name, description, price, category, image_url)
                VALUES (?, ?, ?, ?, ?)
            ''', ('Hoodie', 'Embrace warmth and style with our Cozy Fleece-lined Hooded Sweatshirt. This essential piece features a plush fleece lining that provides exceptional softness and insulation',
                  30.99, 'Clothing', '/static/images/products/hoodie1.jpeg'))

            cursor.execute('''
                INSERT INTO products (name, description, price, category, image_url)
                VALUES (?, ?, ?, ?, ?)
            ''', ('Algorithm Complexity Analysis', 'Analysis of the Complexity of Algorithms is aimed at students of advanced programming courses, dedicated to the study of the analysis of the complexity of algorithms',
                  18.85, 'Book', '/static/images/products/adregoCom.jpeg'))

            cursor.execute('''
                INSERT INTO products (name, description, price, category, image_url)
                VALUES (?, ?, ?, ?, ?)
            ''', ('Algorithms & Data Structures in C', 'This work aims to provide solid competence in the development of medium and high complexity programs and in-depth knowledge of advanced data structures and complex algorithms, using the C programming language and applying the modular programming paradigm',
                  39.95, 'Book', '/static/images/products/adregoAl.jpeg'))

            cursor.execute('''
                INSERT INTO products (name, description, price, category, image_url)
                VALUES (?, ?, ?, ?, ?)
            ''', ('Security in Informatic Networks', 'This book, already considered the classic of Security in Portuguese, warns of the problems that can arise when connecting a machine or local network to the Internet and explains how problems can be reduced or avoided, how vulnerabilities can be detected and minimized. existing and what active and capable protective measures can be taken when interacting with or through the Internet',
                  33.31, 'Book', '/static/images/products/zuqueteSeg.jpeg'))

            cursor.execute('''
                INSERT INTO home_stock (product_id, stock) VALUES
                (1, 30);
            ''')

            cursor.execute('''
                INSERT INTO clothing_stock (product_id, size, stock) VALUES
                (2, 'S', 7),
                (2, 'M', 48),
                (2, 'L', 15),
                (2, 'XL', 31),
                (2, 'XXL', 50);
            ''')

            cursor.execute('''
                INSERT INTO clothing_stock (product_id, size, stock) VALUES
                (3, 'S', 10),
                (3, 'M', 20),
                (3, 'L', 0),
                (3, 'XL', 12),
                (3, 'XXL', 8);
            ''')

            cursor.execute('''
                INSERT INTO book_stock (product_id, stock) VALUES
                (4, 10),
                (5, 10),
                (6, 10);
            ''')

    except Exception as e:
        print(f"Error: {e}")

    conn.commit()
    conn.close()

def show_table_contents():
    try:
        with sqlite3.connect(DB) as conn:
            cursor = conn.cursor()

            tables = [
                ("Users Table:", "SELECT * FROM users;"),
                ("Products Table:", "SELECT * FROM products;"),
                ("Book Products Table:", "SELECT * FROM book_stock;"),
                ("Home Products Table:", "SELECT * FROM home_stock;"),
                ("Clothing Products Table:", "SELECT * FROM clothing_stock;"),
                ("Orders Table:", "SELECT * FROM orders;"),
                ("Order Items Table:", "SELECT * FROM order_items;"),
                ("Product Reviews Table:", "SELECT * FROM reviews;"),
                ("Shopping Cart Table:", "SELECT * FROM shopping_cart;")
            ]

            for table_name, select_query in tables:
                print(f"\033[1m{table_name}\033[0m")
                cursor.execute(select_query)
                for row in cursor.fetchall():
                    print(row)
                print("\n")

    except Exception as e:
        print(f"Error: {e}")

    conn.close()

def drop_all_tables():
    tables = [
        "users",
        "products",
        "clothing_stock",
        "book_stock",
        "home_stock",
        "orders",
        "order_items",
        "reviews",
        "shopping_cart"
    ]
    try:
        with sqlite3.connect(DB) as conn:
            cursor = conn.cursor()

            for table in tables:
                drop_table_query = f"DROP TABLE IF EXISTS {table};"
                cursor.execute(drop_table_query)
                print(f"\033[92mTable '{table}' dropped successfully.\033[0m")

    except Exception as e:
        print(f"Error: {e}")

    conn.close()

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '-s':
            setup()
        elif sys.argv[1] == '-c':
            show_table_contents()
        elif sys.argv[1] == '-d':
            drop_all_tables()
        else:
            print(f"\033[91mUnknown flag: {sys.argv[1]}\033[0m")
    else:
        print("""
\033[93mUsage: -s --> Setup all tables on the database
       -c --> Show content from every table 
       -d --> Delete all content from the database\033[0m
    """)


if __name__ == '__main__':
    main()
