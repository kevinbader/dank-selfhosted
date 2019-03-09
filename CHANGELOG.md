# Changelog
Any breaking or significant changes will be documented in this file with a corresponding Git tag.

# [0.2.0] - 2019-03-09
  - Switch authentication backend from /etc/passwd to LDAP.
  - ypldap is used to provide an NIS translation layer for ldapd.
  - LDAP is used for authentication for the various services (gitea, xmpp, etc) as well as UNIX accounts.
  - dankctl script added to manage users and groups in LDAP.
  - Unexpected things will happen if you have duplicate usernames/uids in /etc/passwd and LDAP. You should plan downtime to perform any necessary account migrations.
  - Matrix (synapse) still uses its internal authentication DB. I'm looking into [mxisd](https://github.com/kamax-matrix/mxisd) for Matrix-LDAP integration for a future release.

# [0.1.0] - 2019-03-09
  - First versioned release.
