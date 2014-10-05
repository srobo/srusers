
import grp
import ldap

from . import sr_ldap
from .sr_ldap import get_conn

# Get a list of all groups
def list(name_filter = None):
    sr_ldap.bind()

    filterstr = "(objectClass=posixGroup)"
    if name_filter != None:
        filterstr = "(&%s(cn=%s))" % (filterstr, name_filter)

    g_res = get_conn().search_st( "ou=groups,o=sr",
                                  ldap.SCOPE_ONELEVEL,
                                  filterstr=filterstr )

    groups = [x[1]["cn"][0] for x in g_res]

    return groups

def uname_from_dn(dn):
    "Extract a username from a dn"
    s = dn.split(",")[0]

    return s[len("uid="):]

def uname_to_dn(uname):
    "Return the user's dn"
    return "uid=%s,ou=users,o=sr" % uname

class group:
    """A group of users"""

    def __init__( self, name ):
        """Initialise the group object.
        Args: name = the name of the group"""
        sr_ldap.bind()

        self.name = name

        #List of new users
        self.new_users = []

        #List of removed users
        self.removed_users = []

        # Some groups require full user dn's in the memberUid field
        self.full_user_dn = False

        if self.name == "shell-users":
            self.full_user_dn = True

        if not self.__load(name):
            #Have to create new
            self.gid = self.__get_new_gidNumber()
            self.in_db = False
            self.members = []
            self.dn = "cn=%s,ou=groups,o=sr" % (name)
            self.desc = "%s group" % name
        else:
            self.in_db = True

    def __load(self, name):
        info = get_conn().search_st( "ou=groups,o=sr",
                                 ldap.SCOPE_ONELEVEL,
                                 filterstr="(&(objectClass=posixGroup)(cn=%s))" % ( name ) )

        if len(info) == 1:
            self.dn = info[0][0]
            self.gid = int( info[0][1]["gidNumber"][0] )

            if "description" in info[0][1]:
                self.desc = info[0][1]["description"][0]
            else:
                self.desc = None

            if "memberUid" in info[0][1].keys():
                self.members = self.__unames_from_dn( info[0][1]["memberUid"] )
            else:
                self.members = []
            return True
        else:
            return False

    def user_add(self, userl, require_case_match = False):
        """Add a user to the group"""
        # Delayed import to avoid circular imports not resolving
        from . import users

        if isinstance(userl, users.user):
            userl = [userl.username]
        # Can't just use "list" as we've got our own function of that name above
        elif type(userl) is not type([]):
            userl = [userl]

        failed = []
        for user in userl:
            # Check the user's real

            if isinstance(user, users.user):
                u = user
            else:
                u = users.user(user, require_case_match)

            if not u.in_db:
                failed.append(user)
                continue

            if u.username not in self.members:
                self.members.append( u.username )
                self.new_users.append( u.username )

        return failed

    def user_rm(self,userl):
        """Remove a user from a group"""
        # Delayed import to avoid circular imports not resolving
        from . import users

        if userl.__class__ is users.user:
            userl = [userl.username]
        # Can't just use "list" as we've got our own function of that name above
        elif type(userl) is not type([]):
            userl = [userl]

        not_members = []
        for user in set(userl):
            if user in self.members:
                self.members.remove(user)
                self.removed_users.append(user)
            else:
                not_members.append(user)

        return not_members

    def rm(self):
        """Delete the group"""
        if not self.in_db:
            raise Exception("Cannot delete group '%s' - doesn't exist in database" % (self.name))
        else:
            get_conn().delete_s( self.dn )
            self.in_db = False
            return True

    def save(self):
        """Save the group"""
        if self.in_db:
            return self.__update()
        else:
            return self.__save_new()

    def __save_new(self):
        modlist = [ ("objectClass", "posixGroup"),
                    ("cn", self.name),
                    ("gidNumber", str(self.gid)),
                    ("description", self.desc) ]

        if len(self.members) > 0:
            modlist.append( ("memberUid", self.__unames_to_dn( self.members ) ) )

        get_conn().add_s( self.dn, modlist )

        self.in_db = True
        self.new_users = []
        self.removed_users = []
        return True

    def __update(self):
        modlist = [ ( ldap.MOD_REPLACE,
                      "memberUid",
                      self.__unames_to_dn( self.members ) ),
                    ( ldap.MOD_REPLACE,
                      "description",
                      self.desc ),
                    ( ldap.MOD_REPLACE,
                      "gidNumber",
                      str(self.gid) ) ]

        get_conn().modify_s( self.dn, modlist )

        self.new_users = []
        self.removed_users = []

    def __get_new_gidNumber( self ):
        """Finds the next available GID"""
        groups = get_conn().search_st( "ou=groups,o=sr",
                                   ldap.SCOPE_ONELEVEL,
                                   filterstr = "(objectClass=posixGroup)",
                                   attrlist = ["gidNumber"] )
        gids = []

        for gid in [int(x[1]["gidNumber"][0]) for x in groups]:
            gids.append(gid)

        gid = 2999
        while True:
            gid += 1

            if gid in gids:
                "An ldap group with that gid already exists"
                continue

            try:
                grp.getgrgid(gid)
            except KeyError:
                "The group isn't in the local stuff either"
                break

        return gid

    def __str__(self):
        desc = ""

        desc = desc + "Group: %s\n" % (self.name)
        desc = desc + "gid: %s\n" % (str(self.gid))
        desc = "%i members: " % ( len(self.members) )

        desc = desc + ", ".join( self.members )

        return desc

    def __unames_from_dn(self, l):
        if self.full_user_dn:
            return [uname_from_dn(x) for x in l]
        return l

    def __unames_to_dn(self, l):
        if self.full_user_dn:
            return [uname_to_dn(x) for x in l]
        return l
