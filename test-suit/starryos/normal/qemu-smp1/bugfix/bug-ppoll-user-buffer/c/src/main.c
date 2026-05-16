/*
 * bug-ppoll-user-buffer: ppoll must not keep direct user pollfd access while
 * blocking, and must copy revents back to the original user buffer on success.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int write_after_delay(int fd)
{
    const struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 100 * 1000 * 1000,
    };
    nanosleep(&delay, NULL);

    const char byte = 'x';
    ssize_t written = write(fd, &byte, 1);
    if (written != 1) {
        printf("child: write failed: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

static int raw_ppoll(struct pollfd *fds, nfds_t nfds,
                     const struct timespec *timeout, const sigset_t *mask)
{
#ifdef SYS_ppoll
    return (int)syscall(SYS_ppoll, fds, nfds, timeout, mask, sizeof(*mask));
#else
    (void)mask;
    int timeout_ms = -1;
    if (timeout != NULL) {
        timeout_ms = (int)(timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000);
    }
    return poll(fds, nfds, timeout_ms);
#endif
}

int main(void)
{
    printf("=== bug-ppoll-user-buffer ===\n");
    printf("Expected: blocking ppoll wakes and writes POLLIN into user revents\n");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        printf("FAIL: pipe failed: %s\n", strerror(errno));
        printf("TEST FAILED\n");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        printf("FAIL: fork failed: %s\n", strerror(errno));
        printf("TEST FAILED\n");
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        int rc = write_after_delay(pipefd[1]);
        close(pipefd[1]);
        _exit(rc);
    }

    close(pipefd[1]);

    struct pollfd pfd = {
        .fd = pipefd[0],
        .events = POLLIN,
        .revents = 0,
    };
    const struct timespec timeout = {
        .tv_sec = 2,
        .tv_nsec = 0,
    };
    sigset_t mask;
    sigemptyset(&mask);

    errno = 0;
    int ret = raw_ppoll(&pfd, 1, &timeout, &mask);
    int saved_errno = errno;

    int status = 0;
    waitpid(pid, &status, 0);

    close(pipefd[0]);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("FAIL: child did not write successfully\n");
        printf("TEST FAILED\n");
        return 1;
    }

    if (ret != 1) {
        printf("FAIL: ppoll returned %d, errno=%d (%s), expected 1\n",
               ret, saved_errno, strerror(saved_errno));
        printf("TEST FAILED\n");
        return 1;
    }

    if ((pfd.revents & POLLIN) == 0) {
        printf("FAIL: ppoll did not write POLLIN to user revents, revents=0x%x\n",
               pfd.revents);
        printf("TEST FAILED\n");
        return 1;
    }

    printf("PASS: ppoll returned 1 and revents=0x%x\n", pfd.revents);
    printf("TEST PASSED\n");
    return 0;
}
