#!/bin/sh
# Debian 等 rootfs 里工具在 /usr/bin；init 进程常无 PATH，须显式设置。
export PATH="/usr/bin:/usr/sbin:/bin:/sbin"

# F-α：fork/exec/wait 诊断；尽早 exec 进静态 bisect，避免与尾部 init hook patch 冲突。
if [ -x /opt/selfhost-tests/test_bisect_1 ]; then
	exec /opt/selfhost-tests/test_bisect_1
fi

export HOME=/root
export USER=root
export HOSTNAME=starry
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# One-crate cargo evidence can bypass the generic /opt/run-tests.sh shell
# wrapper. This keeps init from forking into an extra shell on rootfs images
# where that path exits with a stack-protector abort before the real test runs.
if [ -x /opt/guest-onecrate-inner.sh ]; then
	if [ -r /opt/guest-onecrate-env.sh ]; then
		. /opt/guest-onecrate-env.sh
	fi
	echo "===GUEST_ONECRATE_INIT_DIRECT==="
	exec /bin/bash --noprofile --norc /opt/guest-onecrate-inner.sh
fi

# F-γ：pipe / dup2 / execve 诊断；仅当未注入 /opt/run-tests.sh 时才 exec，避免与 self-host 批量测试抢 init。
if [ ! -x /opt/run-tests.sh ] && [ -x /opt/selfhost-tests/test_pipe_bisect_1 ]; then
	exec /opt/selfhost-tests/test_pipe_bisect_1
fi

printf "Welcome to \033[96m\033[1mStarry OS\033[0m!\n"
# 不要用 Debian rootfs 里的 glibc /usr/bin/env：在 Starry 下偶发退出阶段 stack-smash。
echo

printf "Use \033[1m\033[3mapk\033[0m to install packages.\n"
echo

# Do your initialization here!

cd "$HOME" || cd /
cat > /tmp/starry-shrc <<'EOF'
export PS1='${USER}@${HOSTNAME}:${PWD} # '

# Self-host test hook: 如果 rootfs 注入了 /opt/run-tests.sh，自动跑测试
# 不依赖 stdin，跑完后 echo SELFHOST-DONE 然后退出。
if [ -x /opt/run-tests.sh ]; then
    /opt/run-tests.sh
    echo "===SELFHOST-DONE==="
    exit 0
fi
EOF
export ENV=/tmp/starry-shrc
exec /bin/sh -l -i
