#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#ifndef TCGETS2
#define TCGETS2 0x802C542AUL
#endif

static int open_tty(void)
{
    int fd = open("/dev/tty", O_RDONLY | O_NONBLOCK);
    if (fd >= 0) {
        return fd;
    }
    return STDIN_FILENO;
}

static void fail_errno(const char *what)
{
    printf("TEST FAILED: %s errno=%d (%s)\n", what, errno, strerror(errno));
}

int main(void)
{
    int tty = open_tty();

    struct termios term;
    memset(&term, 0, sizeof(term));
    errno = 0;
    if (ioctl(tty, TCGETS, &term) != 0) {
        fail_errno("TCGETS");
        if (tty != STDIN_FILENO) {
            close(tty);
        }
        return EXIT_FAILURE;
    }

    unsigned char termios2_buf[64];
    memset(termios2_buf, 0, sizeof(termios2_buf));
    errno = 0;
    if (ioctl(tty, TCGETS2, termios2_buf) != 0) {
        fail_errno("TCGETS2");
        if (tty != STDIN_FILENO) {
            close(tty);
        }
        return EXIT_FAILURE;
    }

    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    errno = 0;
    if (ioctl(tty, TIOCGWINSZ, &ws) != 0) {
        fail_errno("TIOCGWINSZ");
        if (tty != STDIN_FILENO) {
            close(tty);
        }
        return EXIT_FAILURE;
    }

    if (tty != STDIN_FILENO) {
        close(tty);
    }

    int p[2];
    if (pipe(p) != 0) {
        fail_errno("pipe");
        return EXIT_FAILURE;
    }

    const char bytes[] = "abc";
    if (write(p[1], bytes, sizeof(bytes)) != (ssize_t)sizeof(bytes)) {
        fail_errno("write pipe");
        close(p[0]);
        close(p[1]);
        return EXIT_FAILURE;
    }

    int available = -1;
    errno = 0;
    if (ioctl(p[0], FIONREAD, &available) != 0) {
        fail_errno("FIONREAD");
        close(p[0]);
        close(p[1]);
        return EXIT_FAILURE;
    }
    close(p[0]);
    close(p[1]);

    if (available != (int)sizeof(bytes)) {
        printf("TEST FAILED: FIONREAD got %d expected %zu\n", available, sizeof(bytes));
        return EXIT_FAILURE;
    }

    printf("TEST PASSED\n");
    return EXIT_SUCCESS;
}
