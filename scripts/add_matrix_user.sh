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

doas -u _synapse /bin/ksh -c ". /usr/local/share/synapse/bin/activate &&
  register_new_matrix_user \
  -c /etc/synapse/homeserver.yaml \
  --no-admin \
  -u '$USERNAME' \
  -p '$PASSWORD' \
  https://localhost:8448"

if [ -n "$EMAIL" ] ; then
  mail -s "Your $DOMAIN Matrix account is ready!" -r "matrix-noreply@$DOMAIN" "$EMAIL" << EOF
Your Matrix account on $DOMAIN has been created!

username: @$USERNAME:$DOMAIN
password: $PASSWORD

CHANGE YOUR PASSWORD IN THE SETTINGS PANEL IMMEDIATELY AFTER YOUR FIRST LOGIN!

To start chatting, download the Riot.im app for Desktop, iOS, or Android:

    https://about.riot.im/downloads/

Enjoy!
EOF

  echo "user $USERNAME created. temporary password sent to $EMAIL"
else
  echo "user $USERNAME created. temporary password: $PASSWORD"
fi
