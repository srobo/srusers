# SRUsers

A wrapper around `python-ldap` for use with a [Student Robotics](https://www.studentrobotics.org)
LDAP instance.

This library is not expected to be used on its own, but instead is consumed
by a number of SR tools, notably:
 * [userman](https://www.studentrobotics.org/git/userman.git) a command-line
   interface to the SR LDAP database
 * [nemesis](https://www.studentrobotics.org/git/nemesis.git)
   (via [libnemesis](https://www.studentrobotics.org/git/libnemesis.git))
   a web application allowing team-leaders to manage the user accounts of
   the competitors they are responsible for

## Dependencies
 * `python-ldap`
 * `Unidecode`

## Configuration
You'll need to create a `local.ini` file next to the `config.ini` which
provides connection details to a suitably set up LDAP database.
See `config.ini` for details of which keys need to be present.
