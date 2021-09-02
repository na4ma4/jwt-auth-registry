#!/bin/sh

set -e

if [ -x "/usr/bin/deb-systemd-helper" ] && [ "$1" = remove ]; then
	deb-systemd-helper stop 'jwt-auth-proxy.service' >/dev/null || exit 1
fi

exit 0
