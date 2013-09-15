import ldap, types
import sr_ldap
import string
import random, hashlib, base64, re
from sr_ldap import get_conn
import groups

def GenPasswd():
    chars = string.letters + string.digits
    newpasswd = ""
    for i in xrange(8):
        newpasswd = newpasswd + random.choice(chars)
    return newpasswd

def encode_pass(p):
    h = hashlib.sha1(p)
    return "{SHA}%s" %( base64.b64encode( h.digest() ) )

def list():
    sr_ldap.bind()

    u_res = get_conn().search_st( "ou=users,o=sr",
                                  ldap.SCOPE_ONELEVEL,
                                  filterstr = "(objectClass=inetOrgPerson)",
                                  attrlist = ["uid"] )
    users = [x[1]["uid"][0] for x in u_res]

    return users

def new_username(college_id, first_name, last_name, tmpset = []):
    """
    Creates a new unique username, taking into account any existing names
    either in the database, plus those in the collection passed.
    @param college_id: either the group name or TLA of the college
    @param first_name: the first name of the user
    @param last_name: the last name of the user
    @param tmpset: a collection of user names that are not valid
    """
    if college_id.startswith(groups.COLLEGE_PREFIX):
        college_tla = college_id[len(groups.COLLEGE_PREFIX):]
    else:
        college_tla = college_id

    prefix = "%s_%s%s" % (college_tla, first_name[0], last_name[0])
    prefix = prefix.lower()

    def c(i):
        return "%s%i" % (prefix, i)

    n = 1
    u = user( c(n) )

    while u.in_db or u.username in tmpset:
        n += 1
        u = user( c(n) )

    return u.username

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

    def __init__( self, username ):
        """Initialise the user object"""
        sr_ldap.bind()

        self.changed_props = []

        if not self.__load( username ):
            uidNumber = self.__get_new_uidNumber()

            self.init_passwd = GenPasswd()

            self.props = { "uid" : username,
                           "objectClass" : ['inetOrgPerson', 'uidObject', 'posixAccount'],
                           "uidNumber" : str(self.__get_new_uidNumber()),
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

    def __load( self, username ):
        info =  get_conn().search_st( "ou=users,o=sr",
                                  ldap.SCOPE_ONELEVEL,
                                  filterstr="(&(objectClass=inetOrgPerson)(uid=%s))" % (username) )

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
            self.props[ self.map[name] ] = [val]

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

                if type(pval) is types.ListType:
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

        for human, z in p.iteritems():
            if first:
                first = False
            else:
                desc = desc + "\n"

            if z in self.props.keys():
                pval = self.props[z]
                if type(pval) is types.ListType:
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
            except ldap.INVALID_CREDENTIALS, ldap.LDAPError:
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
