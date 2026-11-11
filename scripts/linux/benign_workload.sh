#!/usr/bin/env bash
# Benign workload for the false-positive corpus (record-benign-linux.yml).
#
# Ordinary developer and administrator activity on a disposable GitHub-hosted runner: package
# installs, git, a small build and test run, permission changes that do NOT set setuid/setgid,
# reads of cron configuration, shell-history hygiene that is not tampering, and idle time.
# Nothing here is an attack technique. Failures are tolerated (|| true): the goal is telemetry.
set -u

WORK="$(mktemp -d)"
cd "$WORK" || exit 1
GIT=(git -c user.name=ci -c user.email=ci@example.invalid)

echo "::group::packages"
sudo apt-get update -qq || true
# sysstat installs a cron.d entry; that is ordinary package behaviour, kept on purpose.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq tree sysstat || true
python3 -m venv venv || true
# shellcheck disable=SC1091
. venv/bin/activate || true
pip install -q requests pytest || true
pip list --format=freeze | head -n 5 || true
echo "::endgroup::"

echo "::group::git"
mkdir proj && cd proj || exit 1
"${GIT[@]}" init -q
printf 'print("hello")\n' > app.py
"${GIT[@]}" add app.py
"${GIT[@]}" commit -q -m "initial commit"
"${GIT[@]}" branch feature
"${GIT[@]}" tag v0.0.1
"${GIT[@]}" log --oneline
"${GIT[@]}" diff --stat HEAD
"${GIT[@]}" status --short
cd "$WORK" || exit 1
"${GIT[@]}" clone -q --depth 1 https://github.com/samiali38183/tripline.git tripline-src || true
echo "::endgroup::"

echo "::group::build-and-test"
mkdir build && cd build || exit 1
cat > hello.c <<'EOF_C'
#include <stdio.h>
int main(void) { puts("hello"); return 0; }
EOF_C
cat > Makefile <<'EOF_MK'
all: hello
hello: hello.c
	cc -O2 -o hello hello.c
test: hello
	./hello | grep -q hello
clean:
	rm -f hello
EOF_MK
make
make test
mkdir -p pkg tests
printf 'def add(a, b):\n    return a + b\n' > pkg/__init__.py
printf 'from pkg import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n' > tests/test_pkg.py
python -m pytest -q || true
tar czf out.tgz hello pkg
tar tzf out.tgz
find . -name '*.py' -type f | sort
grep -rn "def " pkg
cd "$WORK" || exit 1
echo "::endgroup::"

echo "::group::permissions"
mkdir perms && cd perms || exit 1
touch a.txt b.sh key.txt notes.txt
mkdir -p shared private tmpdir
chmod 644 a.txt
chmod 0644 notes.txt
chmod 755 b.sh
chmod 600 key.txt
chmod 700 private
chmod +x b.sh
chmod u+x b.sh
chmod a+r a.txt
chmod g+w shared
chmod o-rwx private
chmod -R go-w shared
chmod -R 755 shared
chmod 440 notes.txt
chmod 1777 tmpdir
chmod u-s a.txt
/bin/chmod 644 a.txt
/usr/bin/chmod 755 b.sh
sudo chmod 640 notes.txt
sudo chown -R "$(id -un)" shared || true
ls -l
stat -c '%a %n' a.txt b.sh key.txt
cd "$WORK" || exit 1
echo "::endgroup::"

echo "::group::cron-and-history-reads"
crontab -l || true
ls -l /etc/cron.d /etc/cron.daily
cat /etc/crontab
run-parts --test /etc/cron.daily || true
systemctl list-timers --no-pager | head -n 10 || true
logrotate -d /etc/logrotate.conf > /dev/null 2>&1 || true
HISTSIZE=5000 bash -c 'echo history size is set for this shell'
tail -n 5 "$HOME/.bash_history" 2> /dev/null || true
grep -c . "$HOME/.bash_history" 2> /dev/null || true
echo "::endgroup::"

echo "::group::admin-and-network"
uptime
df -h
free -m
ps aux | head -n 5
ss -tln
id
uname -a
sudo systemctl status ssh --no-pager | head -n 5 || true
journalctl -n 10 --no-pager || true
curl -sI https://example.com | head -n 1 || true
wget -q -O /dev/null https://example.com || true
ssh-keygen -q -t ed25519 -N "" -f "$WORK/id_test" || true
openssl rand -hex 8 > /dev/null
echo "::endgroup::"

echo "::group::idle"
for _ in 1 2 3 4; do
  sleep 5
  date +%s > /dev/null
  uptime > /dev/null
done
echo "::endgroup::"

cd / && rm -rf "$WORK"
