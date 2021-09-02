#!/bin/sh

set -e

case "${1}" in
	configure|abort-upgrade|abort-deconfigure|abort-remove)
		if [ -x "/usr/bin/deb-systemd-helper" ]; then
			deb-systemd-helper unmask 'jwt-auth-registry.service' >/dev/null || true
			if deb-systemd-helper --quiet was-enabled 'jwt-auth-registry.service'; then
				deb-systemd-helper enable 'jwt-auth-registry.service' >/dev/null || true
			else
				deb-systemd-helper update-state 'jwt-auth-registry.service' >/dev/null || true
			fi
		fi
	;;
esac

exit 0
