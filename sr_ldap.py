import ldap, sys, getpass

conn = None
bound = False

def connect():
    global conn
    conn = ldap.initialize("ldap://127.0.0.1/")

if conn == None:
    connect()

def default_pass():
    sys.stderr.write("LDAP Password:")
    return ("cn=Manager,o=sr",getpass.getpass(""))

user_callback = default_pass

def set_userinfo( fn ):
    global user_callback
    user_callback = fn

def unbind():
    global conn, bound

    if bound:
        conn.unbind_s()
        bound = False
        connect()

def bind():
    global bound, conn, user_callback

    if not bound:
        info = user_callback()
        try:
            conn.simple_bind_s( info[0], info[1] )
        except ldap.INVALID_CREDENTIALS:
            print "Incorrect password"
            return False

        bound = True
        return True

def get_conn():
    global conn
    return conn
