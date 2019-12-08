
import base64
import hashlib
import ldap
import re
import random
import string
from unidecode import unidecode

from . import constants
from . import sr_ldap
from .sr_ldap import get_conn

try:
    unicode
except NameError:
    unicode = str

def GenPasswd():
    chars = string.ascii_letters + string.digits
    newpasswd = ""
    for i in range(8):
        newpasswd = newpasswd + random.choice(chars)
    return newpasswd

def encode_pass(p):
    h = hashlib.sha1(ensure_bytes(p))
    return "{SHA}%s" %( base64.b64encode( h.digest() ) )

def list():
    sr_ldap.bind()

    u_res = get_conn().search_st( "ou=users,o=sr",
                                  ldap.SCOPE_ONELEVEL,
                                  filterstr = "(objectClass=inetOrgPerson)",
                                  attrlist = ["uid"] )
    users = [x[1]["uid"][0] for x in u_res]

    return users

def ensure_text(string):
    if isinstance(string, bytes):
        return string.decode('utf-8')
    return string

def ensure_bytes(string):
    if isinstance(string, unicode):
        return string.encode('utf-8')
    return string

def new_username(college_id, first_name, last_name, tmpset = []):
    """
    Creates a new unique username, taking into account any existing names
    either in the database, plus those in the collection passed.
    @param college_id: either the group name or TLA of the college
    @param first_name: the first name of the user
    @param last_name: the last name of the user
    @param tmpset: a collection of user names that are not valid
    """
    if college_id.startswith(constants.COLLEGE_PREFIX):
        college_tla = college_id[len(constants.COLLEGE_PREFIX):]
    else:
        college_tla = college_id

    def first_letter(name):
        # unidecode expects a ``unicode`` not a ``str`` otherwise weird results occur
        uname = ensure_text(name)
        # decode the whole name -- not all characters have a conversion,
        # by using the whole name the chances are that one of them will be valid
        dname = unidecode(uname)
        dfirst = dname[0]
        # the rest of the LDAP APIs expect a ``str``
        sfirst = dfirst.encode('utf-8')
        return sfirst

    first = first_letter(first_name)
    last = first_letter(last_name)
    prefix = "%s_%s%s" % (college_tla, first[0], last[0])
    prefix = prefix.lower()

    def c(i):
        return "%s%i" % (prefix, i)

    n = 1
    u = user( c(n), match_case = False )

    while u.in_db or u.username in tmpset:
        n += 1
        u = user( c(n), match_case = False )

    return u.username

def _load(username, match_case):
    username = ensure_bytes(username)
    filter_template = "(&(objectClass=inetOrgPerson)(uid:{0}:={1}))"
    filter_case = 'caseExactMatch' if match_case else 'caseIgnoreMatch'
    info =  get_conn().search_st( "ou=users,o=sr",
                              ldap.SCOPE_ONELEVEL,
                              filterstr = filter_template.format(filter_case, username) )

    return info

class user:
    """A user"""
    map = { "cname" : "cn",
          "sname" : "sn",
          "username" : "uid",
          "id" : "uidNumber",
          "email" : "mail",
          "home" : "homeDirectory",
            "loginShell" : "loginShell" }

    required_props = [ "cn", "sn", "uid", "uidNumber", "mail",
                       "homeDirectory", "objectClass",
                       "gidNumber" ]

    @classmethod
    def search(cls, **kwargs):
        parts = []
        for common, prop in cls.map.items():
            if common in kwargs:
                val = kwargs[common]
                sval = ensure_bytes(val)
                parts.append("({0}={1})".format(prop, sval))

        if len(parts) == 0:
            return None

        parts = ["(objectClass=inetOrgPerson)"] + parts
        sr_ldap.bind()

        filter_str = "(&{0})".format("".join(parts))

        result = get_conn().search_st("ou=users,o=sr",
                                      ldap.SCOPE_ONELEVEL,
                                      filterstr = filter_str,
                                      attrlist = ["uid"])

        userids = [item[1]['uid'][0] for item in result]
        return userids

    @classmethod
    def exists(cls, username, match_case=False):
        info = _load(username, match_case)
        return info != None and len(info) == 1

    def __init__( self, username, match_case = False ):
        """Initialise the user object"""
        sr_ldap.bind()

        self.changed_props = []

        username = ensure_bytes(username)
        if not self.__load( username, match_case ):
            uidNumber = self.__get_new_uidNumber()

            self.init_passwd = GenPasswd()

            self.props = { "uid" : username,
                           "objectClass" : ['inetOrgPerson', 'uidObject', 'posixAccount'],
                           "uidNumber" : str(uidNumber),
                           "gidNumber" : "1999",
                           "homeDirectory" : "/home/%s" % ( username ),
                           "userPassword" : encode_pass( self.init_passwd ),
                           "loginShell" : "/bin/bash"
                           }
            self.dn = "uid=%s,ou=users,o=sr" % (username)

            #All properties are new
            self.changed_props = self.props.keys()

            self.in_db = False

        else:
            self.in_db = True

    def __load( self, username, match_case ):
        info = _load( username, match_case )

        if len(info) == 1:
            self.dn = info[0][0]
            self.props = info[0][1]
            return True
        else:
            return False


    def __get_new_uidNumber( self ):
        """Finds the next available UID"""
        users = get_conn().search_st( "ou=users,o=sr",
                                  ldap.SCOPE_ONELEVEL,
                                  filterstr = "(objectClass=inetOrgPerson)",
                                  attrlist = ["uidNumber"] )
        uids = []

        for uid in [int(x[1]["uidNumber"][0]) for x in users]:
            uids.append(uid)

        uid = 2000
        while uid in uids:
            uid += 1

        return uid

    def __set_prop(self, pname, val):
        self.props[pname] = val

    def __setattr__(self, name, val):
        if name in self.map.keys():
            self.props[ self.map[name] ] = [ensure_bytes(val)]

            if self.map[name] not in self.changed_props:
                self.changed_props.append( self.map[name] )

        else:
            self.__dict__[name] = val

    def save(self):
        self.__check()

        if self.in_db:
            return self.__update()
        else:
            return self.__save_new()

    def delete(self):
        """Deletes the user with the specified username"""

        if not self.in_db:
            raise Exception("Cannot delete user '%s' - doesn't exist in database" % (self.username))
        else:
            get_conn().delete_s( self.dn )
            self.in_db = False
            return True

    def __save_new(self):
        """Save the user as a new item in the database"""
        modlist = []
        for prop in self.props:
            modlist.append( (prop, self.props[prop]) )

        get_conn().add_s( self.dn, modlist )

        self.in_db = True
        self.changed_props = []

        return True

    def __update(self):
        """Update the user in the database"""
        modlist = []
        for prop in self.changed_props:
            modlist.append( (ldap.MOD_REPLACE, prop, self.props[prop]) )

        get_conn().modify_s( self.dn, modlist )
        self.changed_props = []
        return True

    def __missing_props(self):
        """Get a collection of the properties that are missing from this user"""
        required = set(self.required_props)
        actual = set(self.props.keys())
        missing = required - actual
        return missing

    def __check(self):
        """Check that all the required properties are set"""
        missing = self.__missing_props()
        if len(missing) != 0:
            missing_str = "', '".join(missing)
            raise Exception( "Cannot save user '%s' - missing settings: '%s'." % (self.username, missing_str) )

    def __getattr__(self, name):
        if name in self.map.keys():
            if self.map[name] in self.props.keys():
                pval = self.props[ self.map[name] ]

                # Can't just use "list" as we've got our own function of that name above
                if type(pval) is type([]):
                    pval = pval[0]

                return pval
            else:
                return None

        else:
            raise AttributeError("No property '%s'" % (name))

    def __str__(self):
        desc = ""
        p = { "Full name" : "cn",
              "Surname" : "sn",
              "Username" : "uid",
              "ID" : "uidNumber",
              "E-mail" : "mail",
              "Home directory" : "homeDirectory" }
        first = True

        self.props

        for human, z in p.items():
            if first:
                first = False
            else:
                desc = desc + "\n"

            if z in self.props.keys():
                pval = self.props[z]
                # Can't just use "list" as we've got our own function of that name above
                if type(pval) is type([]):
                    pval = pval[0]
            else:
                pval = "None"

            desc = desc + "%s: %s" % (human, pval)

        return desc

    def groups(self):
        """Returns a list of the groups the user is in"""

        filter =  "(&(objectClass=posixGroup)(memberUid=%s))" % ( self.username )

        res = get_conn().search_st( "ou=groups,o=sr",
                                ldap.SCOPE_ONELEVEL,
                                filterstr=filter,
                                attrlist=["cn"] )

        lgroups = [x[1]["cn"][0] for x in res]

        return lgroups

    def bind(self,p):
        if self.in_db:
            sr_ldap.unbind()

            try:
                get_conn().bind_s( self.dn, p )
            except ldap.LDAPError:
                # Most likely are INVALID_CREDENTIALS and UNWILLING_TO_PERFORM
                # The latter occurs for empty passwords, which we don't allow
                return False

            return True

    def __mod_passwd(self,p):
        modlist = [(ldap.MOD_REPLACE, "userPassword", encode_pass( p ) )]
        get_conn().modify_s( self.dn, modlist )
        return True

    def set_passwd(self,old = None,new = None):
        if not self.in_db:
            return False

        if old == None:
            # Modify operation on the db (don't know old pass)
            return self.__mod_passwd(new)
        else:
            get_conn().passwd_s( self.dn, old, new )
            return True

    def get_lang(self):
        "Return the language of the user"
        if not self.in_db:
            raise Exception( "Cannot discover language of user who's not in the DB" )

        g = self.groups()
        for group in g:
            m = re.match( "^lang-(.+)$", group )
            if m != None:
                return m.groups()[0]

    def set_lang(self, lang):
        "Set the language of the user"

        # Delayed import to avoid circular dependency
        from . import groups

        # Remove ourself from any language group we're already in
        g = self.groups()
        for group in g:
            m = re.match( "^lang-(.+)$", group )
            if m != None:
                gi = groups.group(group)

                gi.user_rm( self )
                gi.save()

        g = groups.group( "lang-%s" % lang )
        assert g.in_db
        g.user_add( self )
        g.save()
