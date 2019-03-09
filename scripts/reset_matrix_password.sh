#!/bin/ksh

set -eu

DOMAIN=$(hostname | cut -d. -f2-)

die() {
  >&2 echo "$@"
  exit 1
}

[ $# -lt 1 ] && die "usage: $0 USERNAME [EMAIL]"

USERNAME=$1
PASSWORD=$(pwgen 32 1)
EMAIL=${2:-}

cd /tmp

HASH=$(doas -u _synapse /bin/ksh -c ". /usr/local/share/synapse/bin/activate && hash_password -p '$PASSWORD'")

doas -u _synapse psql synapse -c "UPDATE users SET password_hash='$HASH' WHERE name='@$USERNAME:$DOMAIN'"

if [ -n "$EMAIL" ] ; then
  mail -s "Your $DOMAIN Matrix password has been reset" -r "matrix-noreply@$DOMAIN" "$EMAIL" << EOF
Your Matrix account password for $DOMAIN has been reset.

username: @$USERNAME:$DOMAIN
password: $PASSWORD

CHANGE YOUR PASSWORD IN THE SETTINGS PANEL IMMEDIATELY AFTER YOUR FIRST LOGIN!
EOF

  echo "password for $USERNAME reset. email sent to $EMAIL"
else
  echo "password for $USERNAME reset: $PASSWORD"
fi
