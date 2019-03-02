#!/usr/bin/env perl

# This is a very basic script to ease the maintenance burden of editing LDAP
# users. It can be used to add/remove/modify user accounts, reset passwords,
# etc.
#
# I tried to be robust with the error checking, but, it's freaking perl so
# don't do anything stupid like make it setuid root or put it behind some
# httpd CGI.
#
# It assumes you have a DN with R/W access to the ldap tree (configure this
# in /etc/ldapd.conf) and uses the environment variables LDAP_BINDDN and
# LDAP_BINDPW to authenticate. If these variables are unset it will guess
# your bind DN based on your username and prompt you for the password.
#
#   -cullum

use strict;
use warnings;

use Getopt::Long qw(GetOptionsFromArray :config no_ignore_case);
use File::Basename;
use Net::Domain qw(hostdomain);
use IPC::Open2;
use Net::LDAP;

my $PROG = basename $0;
my $domain = hostdomain();
my $ldap = Net::LDAP->new('localhost') or die "$@\n";
my $basedn = join(',', map { "dc=$_" } split(/\./, $domain));
my $binddn = $ENV{LDAP_BINDDN} // sprintf("uid=%s,ou=users,%s", getlogin(), $basedn);
my $bound = 0;


sub error {
  die "$PROG: $_[0]\n";
}

sub prompt_password {
  my $prompt = shift;
  system '/bin/stty', '-echo';
  print "$prompt: ";
  chomp(my $password = <STDIN>);
  print "\n";
  system '/bin/stty', 'echo';
  return $password;
}

sub bindpw {
  return $ENV{LDAP_BINDPW} if $ENV{LDAP_BINDPW};
  print "Authenticating as $binddn\n";
  return prompt_password('Enter LDAP bind password');
}

sub ldap_bind {
  return if $bound == 1;
  my $r = $ldap->bind($binddn, password => bindpw());
  error "LDAP bind falied: " . $r->error if $r->is_error;
  $bound = 1;
}

sub next_uid {
  my $max = 9999;
  while (my @p = getpwent()) {
    $max = $p[3] if $p[3] > $max && $p[3] >= 10000 && $p[3] < 20000 && $p[3];
  }
  return $max + 1;
}

sub random_password {
  my @alnum = ('a'..'z', 'A'..'Z', 0..9);
  return join '', map $alnum[rand @alnum], 0..32;
}

sub hash_password {
  open2(my $out, my $in, '/usr/bin/encrypt', '-b', 'a');
  print $in "$_[0]\n";
  close $in;
  chomp(my $crypt = <$out>);
  return "{CRYPT}$crypt";
}

sub useradd {
  my $usage =  <<EOF;
Usage: $PROG useradd [options] USERNAME

Options:
  -a, --admin              give the user admin/superuser privileges
  -c, --fullname NAME      first and last name for the new account (required)
  -d, --homedir DIR        home directory of the new account (default: /home/username)
  -h, --help               display this help message and exit
  -K, --keyfile            file containing SSH public keys for the new account
  -k, --key KEY            ssh public key for the new account (can be used multiple times)
  -m, --mail EMAIL         email address for the new account
  -P, --prompt-password    read the account's password from stdin
  -p, --password PASSWORD  password for the new account (default: randomly generated)
  -s, --shell SHELL        login shell of the new account (default: /sbin/nologin)
  -u, --uid UID            user ID of the of the new account (default: next available)
EOF

  my ($username, $fullname, $homedir, $mail, $keyfile, @sshkeys);
  my $shell = '/sbin/nologin';
  my $uid = next_uid();
  my $password = undef;
  my $admin = 0;
  my $prompt_password = 0;

  GetOptionsFromArray(\@_,
    'a|admin'            => \$admin,
    'c|fullname=s'       => \$fullname,
    'd|homedir=s'        => \$homedir,
    'h|help'             => sub { print $usage; exit },
    'K|keyfile=s'        => \$keyfile,
    'k|key=s'            => \@sshkeys,
    'm|mail=s'           => \$mail,
    'P|prompt-password'  => \$prompt_password,
    'p|password=s'       => \$password,
    's|shell=s'          => \$shell,
    'u|uid=i'            => \$uid,
  ) or die $usage;
  $username = shift or die $usage;

  $mail    //= "$username\@$domain";
  $homedir //= "/home/$username";
  my $role = $admin ? 'admin' : 'default';

  error 'invalid username' unless $username =~ /^[[:alnum:]]+$/;
  error 'username already exists' if getpwnam($username);
  error 'groupname already exists' if getgrnam($username);
  error 'no fullname specified' unless $fullname;
  error 'invalid fullname, should be "first last"' unless $fullname =~ /^[\w-]+\s+[\w-]+$/;
  error 'parent of homedir does not exist' unless -d dirname($homedir);
  error 'invalid email address' unless $mail =~ /@/;
  error 'shell is not a valid executable' unless -x $shell;
  error 'invalid uid' if $uid == 0;
  error 'uid already exists' if getpwuid($uid);
  error 'gid already exists' if getgrgid($uid);
  error '--password (-p) and --prompt-password (-P) are mutually exclusive' if ($password && $prompt_password);
  error '--key (-k) and --keyfile (-K) are mutually exclusive' if (@sshkeys && $keyfile);
  error 'keyfile is not readable' if ($keyfile && !(-f $keyfile && -r $keyfile));

  $password = prompt_password("Enter password for $username") if $prompt_password;
  $password //= random_password();
  error 'you must specify a password' if $password =~ /^\s*$/;

  if ($keyfile) {
    open my $fh, "<", $keyfile or error "failed to open keyfile: $!\n";
    chomp (@sshkeys = <$fh>);
  }

  ldap_bind();

  my $r = $ldap->add(
    "cn=$username,ou=groups,$basedn",
    attrs => [
      objectclass => [qw( posixGroup )],
      cn => $username,
      gidNumber => $uid,
      memberUid => $username,
    ]
  );
  error "groupadd failed: " . $r->error if $r->is_error;

  $r = $ldap->add(
    "uid=$username,ou=users,$basedn",
    attrs => [
      objectClass => [qw(
        inetOrgPerson
        posixAccount
        ldapPublicKey
        dankAccount
      )],
      uid => $username,
      cn => $fullname,
      givenName => (split ' ', $fullname)[0],
      sn => (split ' ', $fullname)[1],
      mail => $mail,
      uidNumber => $uid,
      gidNumber => $uid,
      homeDirectory => $homedir,
      loginShell => $shell,
      userPassword => hash_password($password),
      role => $role,
      sshPublicKey => [@sshkeys],
    ]
  );
  if ($r->is_error) {
    $ldap->delete("cn=$username,ou=groups,$basedn");
    error "useradd failed: " . $r->error if $r->is_error;
  }

  if (-d $homedir) {
    print "warning: $homedir already exists\n";
  } else {
    my $ok = 0;
    if ($< == 0) {
      $ok || ($ok |= mkdir $homedir, 0700);
      $ok || ($ok |= chown $uid, $uid, $homedir);
    } else {
      print "invoking doas to create home directory\n";
      my %ENV_COPY = %ENV;
      %ENV = ();
      $ok || ($ok |= system('/usr/bin/doas', '/bin/mkdir', $homedir));
      $ok || ($ok |= system('/usr/bin/doas', '/bin/chmod', '700', $homedir));
      $ok || ($ok |= system('/usr/bin/doas', '/usr/sbin/chown', "$uid:$uid", $homedir));
      %ENV = %ENV_COPY;
    }

    if ($ok != 0) {
      print "rolling back...\n";
      userdel($username);
      error "useradd failed: could not create home directory";
    }
  }
}

sub userdel {
  my $usage =  <<EOF;
Usage: $PROG userdel [options] USERNAME

Options:
  -h, --help    show this help message and exit
EOF

  GetOptionsFromArray(\@_,
    'h|help'        => sub { print $usage; exit },
  ) or die $usage;
  my $username = shift or die $usage;

  error 'invalid username' unless $username =~ /^[[:alnum:]]+$/;

  my $r = $ldap->search(
    base   => "uid=$username,ou=users,$basedn",
    scope  => 'base',
    filter => '(&(objectClass=posixAccount)(objectClass=dankAccount))',
  );
  error "userdel failed: " . $r->error if $r->is_error;

  my $homedir = ($r->entries)[0]->get_value('homeDirectory');

  ldap_bind();

  $r = $ldap->delete("cn=$username,ou=groups,$basedn");
  printf "$PROG: groupdel failed: %s\n", $r->error if $r->is_error;

  $r = $ldap->delete("uid=$username,ou=users,$basedn");
  error "userdel failed: " . $r->error if $r->is_error;

  print "home directory left intact: $homedir\n" if -d $homedir;
}

sub usermod {
  ...
}

sub userlist {
  my $usage =  <<EOF;
Usage: $PROG userlist [options]

Options:
  -c, --colons  use colon delimiter and omit header for easy parsing
  -h, --help    show this help message and exit
EOF

  my $colons = 0;

  GetOptionsFromArray(\@_,
    'c|colons'  => \$colons,
    'h|help'        => sub { print $usage; exit },
  ) or die "$usage\n";

  my $r = $ldap->search(
    base   => "ou=users,$basedn",
    filter => '(&(objectClass=posixAccount)(objectClass=dankAccount))'
  );
  error "userlist failed: " . $r->error if $r->is_error;

  my %users;
  foreach my $e ($r->entries) {
    $users{$e->get_value('uid')} = {
      fullname => scalar $e->get_value('cn'),
      uid      => int $e->get_value('uidNumber'),
      gid      => int $e->get_value('gidNumber'),
      homedir  => scalar $e->get_value('homeDirectory'),
      shell    => scalar $e->get_value('loginShell'),
      mail     => scalar $e->get_value('mail'),
      role     => scalar $e->get_value('role') // 'default',
      locked   => scalar $e->get_value('userPassword') eq '{CRYPT}*',
      sshkeys  => [$e->get_value('sshPublicKey')],
    };
  }

  if (not $colons) {
    printf "%-16s %-16s %-8s %-6s  %-16s %-5s %-5s  %-7s  %s\n",
       qw( username realname role locked shell uid gid sshkeys mail );
    printf "%s\n", '-'x100;
  }

  my $fmt = $colons
    ? "%s:%s:%s:%d:%s:%d:%d:%d:%s\n"
    : "%-16s %-16s %-8s %-6s  %-16s %-5d %-5d  %-7d  %s\n";

  for my $username (sort keys %users) {
    my $u = $users{$username};
    printf $fmt,
      $username,
      $u->{fullname},
      $u->{role},
      $u->{locked} ? ($colons ? 1 : 'yes') : ($colons ? 0 : 'no'),
      $u->{shell},
      $u->{uid},
      $u->{gid},
      scalar @{$u->{sshkeys}},
      $u->{mail};
  }
}

sub resetpass {
  my $usage =  <<EOF;
Usage: $PROG resetpass [options] USERNAME

Options:
  -h, --help               show this help message and exit
  -P, --prompt-password    read the new password from stdin
  -p, --password PASSWORD  password for the new account (default: randomly generated)
EOF

  my $password = undef;
  my $prompt_password = 0;
  my $random_password = 0;

  GetOptionsFromArray(\@_,
    'h|help'        => sub { print $usage; exit },
    'P|prompt-password'  => \$prompt_password,
    'p|password=s'       => \$password,
  ) or die "$usage\n";
  my $username = shift or die $usage;

  error '--password (-p) and --prompt-password (-P) are mutually exclusive' if ($password && $prompt_password);

  $password = prompt_password("Enter password for $username") if $prompt_password;
  unless (defined $password) {
    $password = random_password();
    $random_password = 1;
  }

  error 'you must specify a password' if $password =~ /^\s*$/;

  ldap_bind();

  my $r = $ldap->modify(
    "cn=$username,ou=groups,$basedn",
    replace => {
      userPassword => hash_password($password),
    }
  );

  error "resetpass failed: " . $r->error if $r->is_error;
  print "new password: $password\n" if $random_password;
}

my $usage = <<EOF;
Usage: $PROG COMMAND [options]

Commands:
  help       display this help
  resetpass  reset an account password
  useradd    add a new user
  userdel    delete a user account
  usermod    modify a user account
  userlist   list all users
EOF

my %cmds = (
  resetpass => \&resetpass,
  useradd   => \&useradd,
  userdel   => \&userdel,
  usermod   => \&usermod,
  userlist  => \&userlist,
  help      => sub {print $usage; exit }
);

my $cmd = shift or die $usage;
($cmds{$cmd} || sub {die $usage})->(@ARGV);
