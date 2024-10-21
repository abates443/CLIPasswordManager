import sqlite3


def setup_database():
    # Create or connect to the database
    conn = sqlite3.connect('pwd_mgmt.db')
    # Create a cursor
    cur = conn.cursor()
    # Create a "user_creds" table within the database
    cur.execute('''CREATE TABLE IF NOT EXISTS user_auth 
                    (user_id INTEGER PRIMARY KEY, username TEXT, hash TEXT, unique (username))''')
    cur.execute('''CREATE TABLE IF NOT EXISTS user_creds 
                    (user_id INTEGER, service TEXT, username TEXT, password TEXT, unique (user_id, username, service))''')
    conn.commit()
    cur.close()
    conn.close()


# Add authentication credentials to database
def new_user(username, hash):
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()

    user = username.lower()

    # TEMP TRY STATEMENT TO PREVENT DUPES, REVISE DIFFERENT RETURN VALUES LATER
    try:
        cur.execute('''INSERT INTO user_auth (username, hash) VALUES (?, ?)''', (user, hash))
        conn.commit()
        cur.close()
        conn.close()
        return 1
    except:
        cur.close()
        conn.close()
        return -1


def check_exist(username):
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()

    user = username.lower()
    try:
        cur.execute('''SELECT user_id FROM user_auth WHERE username = ?''', (user,))
        cur.close()
        conn.close()
        return 1
    except:
        cur.close()
        conn.close()
        return -1


def login(username, hash):
    user = username.lower()

    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()

    try:
        cur.execute('''SELECT user_id FROM user_auth WHERE username = ? AND hash = ?''', (user, hash), )
        stored_id = cur.fetchone()[0]
        cur.close()
        conn.close()
        return stored_id
    except:
        cur.close()
        conn.close()
        return -1


def check_auth(id, hash):
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()
    #id = str(id)
    try:
        cur.execute('''SELECT hash FROM user_auth WHERE user_id = ?''', (id,))
        stored_hash = cur.fetchone()[0]
        cur.close()
        conn.close()
        if stored_hash == hash:
            return 1
        else:
            return 0
    except:
        cur.close()
        conn.close()
        return -1


# Add credentials to database
def add_credentials(id, service, username, passwd):
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()

    serv = service.lower()
    user = username.lower()
    id = str(id)

    # TEMP TRY STATEMENT TO PREVENT DUPES, REVISE DIFFERENT RETURN VALUES LATER
    try:
        cur.execute('''INSERT INTO user_creds (user_id, service, username, password) VALUES (?, ?, ?, ?)''', (id, serv, user, passwd))
        conn.commit()
        cur.close()
        conn.close()
        return 1
    except:
        cur.close()
        conn.close()
        return 0


# Retrieve password from database
def retrieve_password(id, service, username):
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()

    serv = service.lower()
    user = username.lower()
    id = str(id)

    # TEMP TRY STATEMENT TO PASS ERROR IF USER/SERVICE PAIR DOES NOT EXIST, REVISE LATER
    try:
        # Select password from the table ONLY IF service, username, and id have an existing match
        cur.execute('''SELECT password FROM user_creds WHERE service = ? AND username = ? AND user_id = ?''', (serv, user, id))
        # Will return the password value
        passwd = cur.fetchone()[0]
        cur.close()
        conn.close()
        return passwd
    except:
        cur.close()
        conn.close()
        return 0


# Delete a set of credentials from database
def delete_credentials(id, service, username):
    serv = service.lower()
    user = username.lower()
    id = str(id)

    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()
    try:
        cur.execute('''DELETE FROM user_creds WHERE service = ? AND username = ? AND user_id = ?''', (serv, user, id))
        conn.commit()

        cur.close()
        conn.close()

        return 1
    except:
        cur.close()
        conn.close()
        return 0


# For testing, show entire table contents
def show_all(id):
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()
    id = str(id)

    cur.execute('''SELECT service, username, password FROM user_creds WHERE user_id = ?''', (id,))
    print("Service : Username : Encrypted Password")
    for service, username, passwd in cur:
        print(service.title() + " : " + username + " : " + str(passwd))

    cur.close()
    conn.close()


# For testing, delete entire table contents
def clear_tables():
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()
    cur.execute('''DELETE FROM user_auth WHERE user_id = 1 OR "1"="1"''')
    conn.commit()
    cur.execute('''DELETE FROM user_creds WHERE user_id = 1 OR "1"="1"''')
    conn.commit()

    cur.close()
    conn.close()


def show_masters():
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()

    cur.execute('''SELECT * FROM user_auth''')
    for user in cur:
        print(user)

    cur.close()
    conn.close()

def show_all_creds():
    conn = sqlite3.connect('pwd_mgmt.db')
    cur = conn.cursor()

    cur.execute('''SELECT * FROM user_creds''')
    for user in cur:
        print(user)

    cur.close()
    conn.close()
