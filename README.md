<p align="center">
    <img src="https://raw.githubusercontent.com/crhenr/openbsd-selfhosted/master/banner.gif">
</p>

# OpenBSD self-hosted

This is the script I use to deploy my self-hosted services on top of OpenBSD. You are free to use and modify it according to your needs. Contributions are also welcome!

**Tested on OpenBSD 6.7**

## Prerequisites

1. This script assumes you are running a fresh OpenBSD system on a public server (e.g., a VPS).
2. You must have a domain name pointing to your server's IP and subdomains (www, git, cloud, and mail).

## Goals

1. Self-hosting my most used services for privacy reasons.
2. Being able to customize my setup and add more features whenever I want.

## Software

### OpenBSD base system:

- acme-client(1): for managing Let's Encrypt certificates.
- httpd(8): nice and simple web server.
- smtpd(8): for managing mails.

### Ports:

- dovecot: for IMAP access.
- Git and cgit: for managing source code repositories.
- PHP: for running RainLoop and Nextcloud.
- PostgreSQL: data storage for Nextcloud.
- rspamd: spam filtering system.

### Web systems:

- RainLoop: a nice UI for the email system.
- Nextcloud: a safe place for all your files.

Please remember to always check the source and not just run some random code on your machine.

## Installation

Just run this command as root:

`curl -fsSL https://raw.githubusercontent.com/crhenr/openbsd-selfhosted/master/setup.sh | sh`

You will be prompt for some basic information required for the configuration files.

## What you will get after installation:

A fully functional self-hosted server for your git repositories, files, and mails.
