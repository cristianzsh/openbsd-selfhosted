#!/bin/sh
# OpenBSD self-hosted script.
# https://github.com/crhenr/openbsd-selfhosted

# Get basic information about the user.
echo -n "What is your domain? "
read domain

echo -n "cgit username: "
read git_title

echo -n "Email username: "
read email_user

# Get passwords.
echo -n "Email password (enter to autogenerate): "
stty -echo
read email_passwd
stty echo

if [ -z "$email_passwd" ]
then
    email_passwd=$(openssl rand -base64 12)
fi
email_user_passwd=$(smtpctl encrypt $email_passwd)

echo -n "\nPostgresql password (enter to autogenerate): "
stty -echo
read postgres_passwd
stty echo

if [ -z "$postgres_passwd" ]
then
    postgres_passwd=$(openssl rand -base64 12)
fi

echo -n "\nNextcloud password (enter to autogenerate): "
stty -echo
read nextcloud_passwd
stty echo

if [ -z "$nextcloud_passwd" ]
then
    nextcloud_passwd=$(openssl rand -base64 12)
fi

git_passwd=$(openssl rand -base64 12)

# Colors:
red="\033[0;31m"
green="\033[0;32m"
reset="\033[0m"

# PHP options:
memory_limit=-1
max_input_time=180
upload_max_filesize=512M
post_max_size=32M


# Install functions.
run_acme() {
    echo "\n${green}[*] Creating acme-client.conf...${reset}"
    cat << EOF > /etc/acme-client.conf
authority letsencrypt {
	api url "https://acme-v02.api.letsencrypt.org/directory"
	account key "/etc/acme/letsencrypt-privkey.pem"
}

authority letsencrypt-staging {
	api url "https://acme-staging-v02.api.letsencrypt.org/directory"
	account key "/etc/acme/letsencrypt-staging-privkey.pem"
}

domain $domain {
	alternative names { www.$domain, git.$domain cloud.$domain mail.$domain }
	domain key "/etc/ssl/private/$domain.key"
	domain certificate "/etc/ssl/$domain.crt"
	domain full chain certificate "/etc/ssl/$domain.pem"
	sign with letsencrypt
}
EOF

    echo "${green}[*] Creating initial httpd.conf...${reset}"
    cat << EOF > /etc/httpd.conf
server "$domain" {
    listen on * port 80

    location "/.well-known/acme-challenge/*" {
        root "/acme"
        request strip 2
    }
}

EOF

    mkdir -p -m 700 /etc/ssl/private
    mkdir -p -m 755 /var/www/acme
    rcctl -f restart httpd
    echo "${green}[*] Generating certificates...${reset}"
    acme-client -v $domain

    if [[ $? != 0 ]]; then
        echo "${red}[-] acme-client failed! Exiting...${reset}"
        exit 1
    fi

    ocspcheck -N -o /etc/ssl/$domain.ocsp.pem /etc/ssl/$domain.pem
    (crontab -l 2>/dev/null; echo "0 0 * * * acme-client $domain && rcctl reload httpd") | crontab -
    (crontab -l 2>/dev/null; echo "0 * * * * ocspcheck -N -o /etc/ssl/$domain.ocsp.pem /etc/ssl/$domain.pem && rcctl reload httpd") | crontab -
}

install_git() {
    echo "${green}[*] Installing and configuring git and cgit...${reset}"
    pkg_add git cgit
    useradd -b /home -m -s /bin/ksh -p $git_passwd git

    cat << EOF > /var/www/conf/cgitrc
# Enable caching of up to 1000 output entries
cache-size=1000

# Cache time to live
cache-dynamic-ttl=5
cache-repo-ttl=5

# Specify the CSS URL
css=/cgit.css

# Show owner on index page
enable-index-owner=0

# Allow HTTP transport Git clone
enable-http-clone=0

# Enable ASCII art commit history graph on the log pages
enable-commit-graph=1

# Show number of affected files per commit on the log pages
enable-log-file-count=1

# Sort branches by date
branch-sort=age

# Add a cgit favicon
favicon=/favicon.ico

# Enable statistics per week, month and quarter
max-stats=quarter

# Set the title and heading of the repository index page
root-title=$git_title's repositories

# Set a subheading for the repository index page
root-desc=

# Allow download of tar.gz, tar.bz2 and zip-files
snapshots=tar.gz

## List of common mimetypes
mimetype.gif=image/gif
mimetype.html=text/html
mimetype.jpg=image/jpeg
mimetype.jpeg=image/jpeg
mimetype.pdf=application/pdf
mimetype.png=image/png
mimetype.svg=image/svg+xml

## Search for these files in the root of the default branch of repositories
## for coming up with the about page:
readme=:README

# Remove .git suffix
remove-suffix=1

scan-path=/srv/git

# Disable adhoc downloads of this repo
repo.snapshots=0

# Disable line-counts for this repo
repo.enable-log-linecount=0

# Restrict the max statistics period for this repo
repo.max-stats=month
EOF

    cat <<EOF >> /etc/httpd.conf
# Git settings
server "git.$domain" {
    listen on * tls port 443

    tls {
        certificate "/etc/ssl/$domain.pem"
        key "/etc/ssl/private/$domain.key"
    }

    location "/.well-known/acme-challenge/*" {
        root "/acme"
        request strip 2
    }

    location "/cgit.*" {
        root "/cgit"
        no fastcgi
    }

    root "/cgi-bin/cgit.cgi"
    fastcgi socket "/run/slowcgi.sock"
}

server "git.$domain" {
    listen on * port 80
    block return 301 "https://git.$domain\$REQUEST_URI"
}

EOF

    mkdir -p /var/www/srv/git
    chown git:git /var/www/srv/git
    mkdir -p /var/www/cgit/cache
    chown www:www /var/www/cgit/cache

    echo "slowcgi_flags=" >> /etc/rc.conf.local
    echo "httpd_flags=" >> /etc/rc.conf.local

    rcctl enable slowcgi httpd
    rcctl -f restart slowcgi httpd
}

install_nextcloud() {
    echo "${green}[*] Installing Nextcloud dependencies...${reset}"
    pkg_add postgresql-server php-7.3.19 php-curl-7.3.19 php-gd-7.3.19 php-intl-7.3.19 php-pdo_pgsql-7.3.19 php-zip-7.3.19

    cp /etc/php-7.3.sample/* /etc/php-7.3
    mkdir -p /var/www/etc/ssl
    cp /etc/resolv.conf /var/www/etc/resolv.conf
    cp /etc/ssl/cert.pem /var/www/etc/ssl/cert.pem
    cp /etc/ssl/openssl.cnf /var/www/etc/ssl/openssl.cnf
    chown -R www:www /var/www/etc

    echo "${green}[*] Configuring PostgreSQL...${reset}"
    mkdir /var/postgresql/data
    chown _postgresql:_postgresql /var/postgresql/data

    echo $postgres_passwd > /tmp/pwfile.txt
    su _postgresql -c 'initdb -D /var/postgresql/data -U postgres -A md5 --pwfile=/tmp/pwfile.txt'
    rm /tmp/pwfile.txt

    export PGPASSWORD=$postgres_passwd
    rcctl start postgresql
    su _postgresql -c "psql -d template1 -U postgres -c \"CREATE USER nextcloud WITH PASSWORD '$nextcloud_passwd';\""
    su _postgresql -c "psql -d template1 -U postgres -c \"CREATE DATABASE nextcloud\""
    su _postgresql -c "psql -d template1 -U postgres -c \"GRANT ALL PRIVILEGES ON DATABASE nextcloud to nextcloud;\""
    unset PGPASSWORD

    echo "${green}[*] Downloading Nextcloud...${reset}"
    ftp https://download.nextcloud.com/server/releases/nextcloud-18.0.6.tar.bz2
    tar xjvf nextcloud-18.0.6.tar.bz2 -C /var/www/
    rm nextcloud-18.0.6.tar.bz2

    echo "${green}[*] Configuring Nextcloud...${reset}"
    cat << EOF > /var/www/nextcloud/config/custom.config.php
<?php
\$CONFIG = array (
'datadirectory' => ((php_sapi_name() == 'cli') ? '/var/www' : '') . '/nextcloud/data',
);
EOF

    cat << EOF >> /etc/httpd.conf
# Nextcloud settings
server "cloud.$domain" {
    listen on * tls port 443
    root "/nextcloud"
    directory index "index.php"

    tls {
        certificate "/etc/ssl/$domain.pem"
        key "/etc/ssl/private/$domain.key"
    }

    connection max request body 537919488
    location "/.well-known/acme-challenge/*" {
            root "/acme"
            request strip 2
    }

    # Deny access to the specified files
    location "/db_structure.xml"    { block }
    location "/.ht*"                { block }
    location "/README"              { block }
    location "/data*"               { block }
    location "/config*"             { block }
    location "/build*"              { block }
    location "/tests*"              { block }
    location "/config*"             { block }
    location "/lib*"                { block }
    location "/3rdparty*"           { block }
    location "/templates*"          { block }
    location "/data*"               { block }
    location "/.user*"              { block }
    location "/autotest*"           { block }
    location "/occ*"                { block }
    location "/issue*"              { block }
    location "/indie*"              { block }
    location "/db_*"                { block }
    location "/console*"            { block }

    location "/*.php*" {
        fastcgi socket "/run/php-fpm.sock"
    }

    location "/.well-known/host-meta" {
        block return 301 "/public.php?service=host-meta"
    }

    location "/.well-known/host-meta.json" {
        block return 301 "/public.php?service=host-meta-json"
    }

    location "/.well-known/webfinger" {
        block return 301 "/public.php?service=webfinger"
    }

    location "/.well-known/carddav" {
        block return 301 "/remote.php/dav/"
    }

    location "/.well-known/caldav" {
        block return 301 "/remote.php/dav/"
    }
}

server "cloud.$domain" {
    listen on * port 80
    block return 301 "https://cloud.$domain\$REQUEST_URI"
}

EOF

    sed -i "s/\(memory_limit *=*\).*/\1 $memory_limit/" /etc/php-7.3.ini
    sed -i "s/\(max_input_time *=*\).*/\1 $max_input_time/" /etc/php-7.3.ini
    sed -i "s/\(upload_max_filesize *=*\).*/\1 $upload_max_filesize/" /etc/php-7.3.ini
    sed -i "s/\(post_max_size *=*\).*/\1 $post_max_size/" /etc/php-7.3.ini

    sed -i "/opcache.enable=1/s/^;//" /etc/php-7.3.ini
    sed -i "/opcache.memory_consumption=128/s/^;//" /etc/php-7.3.ini
    sed -i "/opcache.interned_strings_buffer=8/s/^;//" /etc/php-7.3.ini
    sed -i "/opcache.max_accelerated_files=10000/s/^;//" /etc/php-7.3.ini
    sed -i "/opcache.save_comments=1/s/^;//" /etc/php-7.3.ini

    sed -i "s/;opcache.enable_cli=0/opcache.enable_cli=1/" /etc/php-7.3.ini
    sed -i "s/;opcache.revalidate_freq=2/opcache.revalidate_freq=1/" /etc/php-7.3.ini

    chown -R www:www /var/www/nextcloud
    rcctl enable postgresql php73_fpm httpd
    rcctl restart postgresql php73_fpm httpd
}

configure_email() {
    echo "${green}[*] Installing email dependencies...${reset}"
    pkg_add opensmtpd-extras opensmtpd-filter-rspamd dovecot dovecot-pigeonhole rspamd redis

    echo "${green}[*] Configuring OpenSMTPD...${reset}"
    cat << EOF > /etc/mail/smtpd.conf
pki "mail.$domain" cert "/etc/ssl/$domain.crt"
pki "mail.$domain" key "/etc/ssl/private/$domain.key"

table aliases file:/etc/mail/aliases
table credentials passwd:/etc/mail/credentials
table virtuals file:/etc/mail/virtuals

filter "rspamd" proc-exec "/usr/local/libexec/smtpd/filter-rspamd"

listen on all tls pki "mail.$domain" hostname "mail.$domain" filter "rspamd"
listen on egress port submission tls-require pki "mail.$domain" hostname "mail.$domain" auth <credentials> filter "rspamd"

action "local_mail" mbox alias <aliases>
action "domain_mail" maildir "/var/vmail/$domain/%{dest.user}" virtual <virtuals>
action "outbound" relay

match from any for domain "$domain" action "domain_mail"
match from local for local action "local_mail"

match from local for any action "outbound"
match auth from any for any action "outbound"
EOF

    printf "$email_user@$domain:$email_user_passwd:vmail:2000:2000:/var/vmail/$domain/$email_user::userdb_mail=maildir:/var/vmail/$domain/$email_user\n" > /etc/mail/credentials

    echo "${green}[*] Configuring Dovecot...${reset}"
    chmod 0440 /etc/mail/credentials
    useradd -c "Virtual Mail Account" -d /var/vmail -s /sbin/nologin -u 2000 -g =uid -L staff vmail
    mkdir /var/vmail
    chown _smtpd:_dovecot /etc/mail/credentials
    chown vmail:vmail /var/vmail

    cat << EOF > /etc/mail/virtuals
abuse@$domain:          $email_user@$domain
hostmaster@$domain:     $email_user@$domain
postmaster@$domain:     $email_user@$domain
webmaster@$domain:      $email_user@$domain
$email_user@$domain:    vmail
EOF

    cat << EOF >> /etc/login.conf

dovecot:\\
    :openfiles-cur=1024:\\
    :openfiles-max=2048:\\
    :tc=daemon:
EOF

    cat << EOF > /etc/dovecot/local.conf
auth_mechanisms = plain
first_valid_uid = 2000
first_valid_gid = 2000
mail_location = maildir:/var/vmail/%d/%n
mail_plugin_dir = /usr/local/lib/dovecot
managesieve_notify_capability = mailto
managesieve_sieve_capability = fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex  imap4flags copy include variables body enotify environment mailbox date index ihave duplicate mime foreverypart extracttext imapsieve vnd.dovecot.imapsieve
mbox_write_locks = fcntl
mmap_disable = yes
namespace inbox {
    inbox = yes
    location =
    mailbox Archive {
        auto = subscribe
        special_use = \\Archive
    }
    mailbox Drafts {
        auto = subscribe
        special_use = \\Drafts
    }
    mailbox Junk {
        auto = subscribe
        special_use = \\Junk
    }
    mailbox Sent {
        auto = subscribe
        special_use = \\Sent
    }
    mailbox Trash {
        auto = subscribe
        special_use = \\Trash
    }
    prefix =
}
passdb {
    args = scheme=CRYPT username_format=%u /etc/mail/credentials
    driver = passwd-file
    name =
}
plugin {
    imapsieve_mailbox1_before = file:/usr/local/lib/dovecot/sieve/report-spam.sieve
    imapsieve_mailbox1_causes = COPY
    imapsieve_mailbox1_name = Junk
    imapsieve_mailbox2_before = file:/usr/local/lib/dovecot/sieve/report-ham.sieve
    imapsieve_mailbox2_causes = COPY
    imapsieve_mailbox2_from = Junk
    imapsieve_mailbox2_name = *
    sieve = file:~/sieve;active=~/.dovecot.sieve
    sieve_global_extensions = +vnd.dovecot.pipe +vnd.dovecot.environment
    sieve_pipe_bin_dir = /usr/local/lib/dovecot/sieve
    sieve_plugins = sieve_imapsieve sieve_extprograms
}
protocols = imap sieve
service imap-login {
    inet_listener imaps {
        port = 0
    }
}
service managesieve-login {
    inet_listener sieve {
        port = 4190
    }
    inet_listener sieve_deprecated {
        port = 2000
    }
}
ssl_cert = </etc/ssl/$domain.crt
ssl_key = </etc/ssl/private/$domain.key
userdb {
    args = username_format=%u /etc/mail/credentials
    driver = passwd-file
    name =
}
protocol imap {
    mail_plugins = " imap_sieve"
}
EOF

    cat << EOF > /usr/local/lib/dovecot/sieve/report-ham.sieve
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.mailbox" "*" {
    set "mailbox" "\${1}";
}

if string "\${mailbox}" "Trash" {
    stop;
}

if environment :matches "imap.user" "*" {
    set "username" "\${1}";
}

pipe :copy "sa-learn-ham.sh" [ "\${username}" ];
EOF

    cat << EOF > /usr/local/lib/dovecot/sieve/report-spam.sieve
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.user" "*" {
    set "username" "\${1}";
}

pipe :copy "sa-learn-spam.sh" [ "\${username}" ];
EOF

    sed -i "/ssl_cert*/s/^/#/" /etc/dovecot/conf.d/10-ssl.conf
    sed -i "/ssl_key*/s/^/#/" /etc/dovecot/conf.d/10-ssl.conf

    sievec /usr/local/lib/dovecot/sieve/report-ham.sieve
    sievec /usr/local/lib/dovecot/sieve/report-spam.sieve

    cat << EOF > /usr/local/lib/dovecot/sieve/sa-learn-ham.sh
#!/bin/sh
exec /usr/local/bin/rspamc -d "\${1}" learn_ham
EOF

    cat << EOF > /usr/local/lib/dovecot/sieve/sa-learn-spam.sh
#!/bin/sh
exec /usr/local/bin/rspamc -d "\${1}" learn_spam
EOF

    chmod 0755 /usr/local/lib/dovecot/sieve/sa-learn-ham.sh
    chmod 0755 /usr/local/lib/dovecot/sieve/sa-learn-spam.sh

    mkdir /etc/mail/dkim && cd /etc/mail/dkim
    openssl genrsa -out private.key 1024
    openssl rsa -in private.key -pubout -out public.key
    chmod 0440 private.key
    chown root:_rspamd private.key && cd

    cat << EOF > /etc/rspamd/local.d/dkim_signing.conf
domain {
    $domain {
        path = "/etc/mail/dkim/$domain.key";
        selector = "changethis";
    }
}
EOF

    echo "\n${green}[*] Installing RainLoop dependencies...${reset}"
    pkg_add php-7.3.19 php-curl-7.3.19 php-pdo_sqlite-7.3.19 php-zip-7.3.19 pecl73-mcrypt unzip-6.0p13

    echo "\n${green}[*] Downloading RainLoop...${reset}"
    ftp https://www.rainloop.net/repository/webmail/rainloop-latest.zip
    unzip rainloop-latest.zip -d /var/www/htdocs/rainloop
    rm rainloop-latest.zip

    cat << EOF >> /etc/httpd.conf
# RainLoop settings
server "mail.$domain" {
    listen on * tls port 443
    root "/htdocs/rainloop"
    directory index "index.php"

    tcp { nodelay, backlog 10 }

    tls {
        certificate "/etc/ssl/$domain.crt"
        key "/etc/ssl/private/$domain.key"
    }

    hsts {
        max-age 31556952
        preload
    }

    connection max request body 26214400

    location "/data*" {
        block return 403
    }

    location "*.php*" {
        fastcgi socket "/run/php-fpm.sock"
    }
}

server "mail.$domain" {
    listen on * port 80
    block return 301 "https://mail.$domain\$REQUEST_URI"
}

EOF

    mkdir /var/www/etc
    cp /etc/resolv.conf /var/www/etc/resolv.conf
    chown -R www:www /var/www/htdocs/rainloop
    rcctl enable smtpd dovecot redis rspamd httpd
    rcctl restart smtpd dovecot redis rspamd httpd
}

run_acme
install_git
install_nextcloud
configure_email

echo "

***************************************************************************************
--> Important information

${green}[*]${reset} Domain:                   ${green}$domain${reset}
${green}[*]${reset} Email address:            $email_user@$domain
                              Password: ${red}$email_passwd${reset}

${green}[*]${reset} Passwords:
    - Git:                    ${red}$git_passwd${reset}
    - Postgres:               ${red}$postgres_passwd${reset}
    - Nextcloud database:     ${red}$nextcloud_passwd${reset}

${green}[*]${reset} Next steps:
    1) Configure Nextcloud at cloud.$domain
        - Database user: nextcloud
        - Database password: $nextcloud_passwd
        - Database name: nextcloud
    2) Change the RainLoop admin password at mail.$domain/?admin (default is 12345)
    3) Add your public SSH key at /home/git/.ssh/authorized_keys
    4) Create the DKIM and DMARC records:
        - Check the /etc/rspamd/local.d/dkim_signing.conf and /etc/mail/dkim/public.key
          files and follow the instructions given by your registrar.

***************************************************************************************

OpenBSD self-hosted script.
Made with <3 by @crhenr
https://github.com/crhenr/openbsd-selfhosted
"
