#!/bin/sh
# Build one client implementation for API and all-in-one on their runtime ABI.
# Debian trixie has no CVE-2026-60002 fix. Remove this source-build boundary
# once its openssh-client package carries the upstream lifetime repair.
# Upgrade version AND checksum together from https://www.openssh.org/releasenotes.html.
set -eu
OPENSSH_VERSION=10.6p1
OPENSSH_SHA256=a9dc9565dffe8640f64d863cd29a32bc4a3dbdec0566a7fc44c5d6ee767d5f39
SOURCE_URL="https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz"
OUT=/out
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM
cd "$BUILD_DIR"
curl --fail --show-error --silent --location --retry 3 --proto '=https' --tlsv1.2 \
    "$SOURCE_URL" -o openssh.tar.gz
printf '%s  openssh.tar.gz\n' "$OPENSSH_SHA256" | sha256sum --check --strict -
tar -xzf openssh.tar.gz
cd "openssh-${OPENSSH_VERSION}"
# /usr/bin/ssh is compiled into scp/sftp: keep one path, not a PATH shadow
# over a vulnerable distro binary. GSSAPI, FIDO and interactive sftp remain
# available, alongside the deployer's password and batch key authentication.
./configure --prefix=/usr --sysconfdir=/etc/ssh --libexecdir=/usr/lib/openssh \
    --with-kerberos5 --with-libedit --with-security-key-builtin
CLIENTS='ssh scp sftp ssh-add ssh-agent ssh-keygen ssh-keyscan'
HELPERS='ssh-pkcs11-helper ssh-sk-helper'
# Deliberately do not make install: that also installs sshd and a setuid
# ssh-keysign. Host-based authentication is unused by the deployment service.
make -j "$(getconf _NPROCESSORS_ONLN)" $CLIENTS $HELPERS
install -d "$OUT/usr/bin" "$OUT/usr/lib/openssh" "$OUT/etc/ssh/ssh_config.d" \
    "$OUT/usr/share/doc/openssh-client" "$OUT/usr/share/shapoclyack"
for program in $CLIENTS; do
    install -m 0755 "$program" "$OUT/usr/bin/$program"
done
for program in $HELPERS; do
    install -m 0755 "$program" "$OUT/usr/lib/openssh/$program"
done
# Keep the Debian client configuration convention, including the directory
# where operators mount settings. Do not generate host or client private keys.
cat > "$OUT/etc/ssh/ssh_config" <<'CONFIG'
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
CONFIG
chmod 0644 "$OUT/etc/ssh/ssh_config"
install -m 0644 LICENCE "$OUT/usr/share/doc/openssh-client/copyright"
printf 'OpenSSH %s\nsource=%s\nsha256=%s\n' "$OPENSSH_VERSION" "$SOURCE_URL" "$OPENSSH_SHA256" \
    > "$OUT/usr/share/shapoclyack/openssh-build.txt"
"$OUT/usr/bin/ssh" -V 2>&1 | grep -F "OpenSSH_${OPENSSH_VERSION}"
# Check staged contents rather than only the version banner.
test "$(find "$OUT" -type f -perm /6000 | wc -l)" -eq 0
test ! -e "$OUT/usr/sbin/sshd"
test ! -e "$OUT/usr/lib/openssh/ssh-keysign"
