import ldap, sys, getpass
from ConfigParser import NoOptionError
from config import config

conn = None
bound = False

def connect():
    global conn
    conn_str = "ldap://%s/" % config.get('ldap', 'host')
    conn = ldap.initialize(conn_str)

if conn == None:
    connect()

def default_pass():
    try:
        passwd = config.get('ldap', 'password')
    except NoOptionError:
        sys.stderr.write("LDAP Password:")
        passwd = getpass.getpass("")
    conn_str = "cn=%s,o=sr" % config.get('ldap', 'username')
    return (conn_str, passwd)

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
