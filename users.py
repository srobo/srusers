import ldap, types
import sr_ldap
import string
import random, hashlib, base64
from sr_ldap import get_conn

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
        if not self.__check():
            raise "Cannot save - missing setting"

        if self.in_db:
            return self.__update()
        else:
            return self.__save_new()

    def delete(self):
        """Deletes the user with the specified username"""

        if not self.in_db:
            raise "Cannot delete user - doesn't exist in database"
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

    def __check(self):
        """Check that all the required properties are set"""
        for req in self.required_props:
            if req not in self.props.keys():
                return False
        return True

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

        groups = [x[1]["cn"][0] for x in res]

        return groups
    
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
        
        
    
