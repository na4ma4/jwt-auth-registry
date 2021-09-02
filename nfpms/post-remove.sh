#!/bin/sh

set -e

if [ "$1" = "remove" ]; then
	if [ -x "/usr/bin/deb-systemd-helper" ]; then
		deb-systemd-helper mask 'jwt-auth-registry.service' >/dev/null || true
	fi
fi

if [ "$1" = "purge" ]; then
	if [ -x "/usr/bin/deb-systemd-helper" ]; then
		deb-systemd-helper purge 'jwt-auth-registry.service' >/dev/null || true
		deb-systemd-helper unmask 'jwt-auth-registry.service' >/dev/null || true
	fi
fi

exit 0
