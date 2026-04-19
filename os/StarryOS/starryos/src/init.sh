#!/bin/sh

# F-α：fork/exec/wait 诊断；尽早 exec 进静态 bisect，避免与尾部 init hook patch 冲突。
if [ -x /opt/selfhost-tests/test_bisect_1 ]; then
	exec /opt/selfhost-tests/test_bisect_1
fi

export HOME=/root
export USER=root
export HOSTNAME=starry

printf "Welcome to \033[96m\033[1mStarry OS\033[0m!\n"
env
echo

printf "Use \033[1m\033[3mapk\033[0m to install packages.\n"
echo

# Do your initialization here!

cd "$HOME" || cd /
export PS1='${USER}@${HOSTNAME}:${PWD} # '
exec /bin/sh -i
