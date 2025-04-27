#include <pl_readline.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termio.h>
#include <unistd.h>

int getch(void) {
    struct termios tm, tm_old;
    int fd = 0;

    if (tcgetattr(fd, &tm) < 0)
        return -1;

    tm_old = tm;
    cfmakeraw(&tm);

    if (tcsetattr(fd, TCSANOW, &tm) < 0)
        return -1;

    int ch = getchar();

    if (tcsetattr(fd, TCSANOW, &tm_old) < 0)
        return -1;

    if (ch == 0x0d) {
        return PL_READLINE_KEY_ENTER;
    }
    if (ch == 0x7f) {
        return PL_READLINE_KEY_BACKSPACE;
    }
    if (ch == 0x9) {
        return PL_READLINE_KEY_TAB;
    }
    if (ch == 0x1b) {
        ch = getch();
        if (ch == '[') {
            ch = getch();
            switch (ch) {
            case 'A':
                return PL_READLINE_KEY_UP;
            case 'B':
                return PL_READLINE_KEY_DOWN;
            case 'C':
                return PL_READLINE_KEY_RIGHT;
            case 'D':
                return PL_READLINE_KEY_LEFT;
            case 'H':
                return PL_READLINE_KEY_HOME;
            case 'F':
                return PL_READLINE_KEY_END;
            case '5':
                if (getch() == '~')
                    return PL_READLINE_KEY_PAGE_UP;
                break;
            case '6':
                if (getch() == '~')
                    return PL_READLINE_KEY_PAGE_DOWN;
                break;
            default:
                return -1;
            }
        }
    }
    return ch;
}

void flush(void) { fflush(stdout); }

void handle_tab(char *buf, pl_readline_words_t words) {
    (void)buf;
    pl_readline_word_maker_add("ls", words, true, ' ');
    pl_readline_word_maker_add("echo", words, true, ' ');
    pl_readline_word_maker_add("cat", words, true, ' ');
    pl_readline_word_maker_add("ps", words, true, ' ');
    pl_readline_word_maker_add("foo", words, false, ' ');
    pl_readline_word_maker_add("bar", words, false, ' ');
}

int main(void) {
    pl_readline_t pl =
        pl_readline_init(getch, (void (*)(int))putchar, flush, handle_tab);
    while (1) {
        const char *buffer = pl_readline(pl, "\033[1;32m[user@localhost]$\033[0m ");
        printf("Your input: %s\n", buffer);
        if (strcmp(buffer, "exit") == 0)
            break;
    }
    pl_readline_uninit(pl);
}
