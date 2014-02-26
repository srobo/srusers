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

    # Annoyance: all SR users are under the ou=users subtree, except for
    # the Manager entity, which isn't a user. Work around this corner case.
    username = config.get('ldap', 'username')
    if username == "Manager":
        conn_str = "cn={0},o=sr".format(username)
    else:
        conn_str = "uid={0},ou=users,o=sr".format(username)

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
