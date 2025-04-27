#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <aether/window.h>
#include "pl_readline.h"

#define SHELL_WINDOW_WIDTH 800
#define SHELL_WINDOW_HEIGHT 600

uint64_t window_buffer = 0;

char *path = NULL;
bool exited = false;

uint32_t *color_map = NULL;
uint64_t width = 0;
uint64_t height = 0;

void window_resize_handler()
{
    if (color_map)
    {
        free(color_map);
    }

    window_info_t info;
    get_window_info(&info);

    width = info.width;
    height = info.height;

    color_map = malloc(width * height * sizeof(uint32_t));
}

int getc()
{
    int ch;
    while ((ch = (int)getchar()) == 0)
        __asm__ __volatile__("pause");
    switch (ch)
    {
    case '\b':
        return PL_READLINE_KEY_BACKSPACE;
    case '\t':
        return PL_READLINE_KEY_TAB;
    case '\n':
        return PL_READLINE_KEY_ENTER;
    case -1:
        return PL_READLINE_KEY_UP;
    case -2:
        return PL_READLINE_KEY_DOWN;
    case -3:
        return PL_READLINE_KEY_LEFT;
    case -4:
        return PL_READLINE_KEY_RIGHT;
    default:
        return ch;
    }
}

char vsprintf_buf[4096];

void putc(int ch)
{
    printf("%c", ch);
}

void flush()
{
}

static void handle_tab(char *buf, pl_readline_words_t words)
{
    pl_readline_word_maker_add("cd", words, true, ' ');
    pl_readline_word_maker_add("clear", words, true, ' ');
    pl_readline_word_maker_add("ls", words, true, ' ');
    pl_readline_word_maker_add("run", words, true, ' ');

    if (buf[0] != '/' && strlen(buf))
    {
        return;
    }

    int fd = open(buf, 0, 0);
    dirent_t dents[128];
    int num = getdents(fd, dents, 128);
    if (num < 0)
    {
        close(fd);
        return;
    }

    for (int i = 0; i < num; i++)
    {
        // char *new_path = pathacat(s, dents[i].name);
        // pl_readline_word_maker_add(new_path, words, false, dents[i].type == file_dir ? '/' : ' ');
        pl_readline_word_maker_add(dents[i].name, words, false, dents[i].type == file_dir ? '/' : ' ');
    }

    // free(s);

    close(fd);
}

int list_files(char *path, int argc, char **argv)
{
    if (argc == 2)
    {
        path = argv[1];
    }

    int fd = open((const char *)path, 0, 0);

    dirent_t dents[128];
    int num = getdents(fd, dents, 128);
    if (num < 0)
    {
        return num;
    }

    for (int i = 0; i < num; i++)
    {
        if (dents[i].type == file_dir)
            printf("\033[1;34m%s\033[m ", dents[i].name);
        else
            printf("%s ", dents[i].name);
    }
    printf("\n");

    close(fd);

    return 0;
}

#define MAX_ARGC 64
#define MAX_ARG_LEN 256

typedef enum
{
    STATE_DEFAULT,
    STATE_SINGLE_QUOTE,
    STATE_DOUBLE_QUOTE,
    STATE_ESCAPE
} parse_state;

char **parse_command(const char *input, int *argc)
{
    char **argv = malloc(MAX_ARGC * sizeof(char *));
    char current_arg[MAX_ARG_LEN];
    int arg_len = 0;
    parse_state state = STATE_DEFAULT;
    *argc = 0;

    for (const char *p = input; *p != '\0'; p++)
    {
        char c = *p;

        switch (state)
        {
        case STATE_DEFAULT:
            if (c == '\\')
            {
                state = STATE_ESCAPE;
            }
            else if (c == '\'')
            {
                state = STATE_SINGLE_QUOTE;
            }
            else if (c == '"')
            {
                state = STATE_DOUBLE_QUOTE;
            }
            else if (c == ' ' || c == '\t')
            {
                if (arg_len > 0)
                {
                    current_arg[arg_len] = '\0';
                    argv[(*argc)++] = strdup(current_arg);
                    arg_len = 0;
                }
            }
            else
            {
                current_arg[arg_len++] = c;
            }
            break;

        case STATE_SINGLE_QUOTE:
            if (c == '\'')
            {
                state = STATE_DEFAULT;
            }
            else
            {
                current_arg[arg_len++] = c;
            }
            break;

        case STATE_DOUBLE_QUOTE:
            if (c == '"')
            {
                state = STATE_DEFAULT;
            }
            else if (c == '\\')
            {
                state = STATE_ESCAPE;
            }
            else
            {
                current_arg[arg_len++] = c;
            }
            break;

        case STATE_ESCAPE:
            current_arg[arg_len++] = c;
            state = (state == STATE_DOUBLE_QUOTE) ? STATE_DOUBLE_QUOTE : STATE_DEFAULT;
            break;
        }

        if (arg_len >= MAX_ARG_LEN - 1 || *argc >= MAX_ARGC - 1)
        {
            break; // 防止缓冲区溢出
        }
    }

    // 处理最后一个参数
    if (arg_len > 0)
    {
        current_arg[arg_len] = '\0';
        argv[(*argc)++] = strdup(current_arg);
    }

    argv[*argc] = NULL; // 以NULL结尾
    return argv;
}

int run_exec(const char *name, char **argv, char **envp)
{
    int fd = open(name, 0, 0);
    if (fd <= 0)
    {
        printf("%s: file not found\n", name);
        return -ENOENT;
    }

    close(fd);

    int status = 0;

    int pid = fork();
    if (pid == 0)
    {
        execve(name, argv, envp);
        exit(-1);
    }
    else
    {
        waitpid(pid, &status);
    }

    if (status < 0)
        printf("Child process exited with error code: %d\n", status);

    return status;
}

static int shell_exec(char *path, const char *command)
{
    if (!strlen((char *)command))
        return 0;

    int argc = 0;
    char **argv = parse_command(command, &argc);

    int retcode = 0;
    if (!strcmp(argv[0], "ls"))
    {
        retcode = list_files(path, argc, argv);
    }
    else if (!strcmp(argv[0], "clear"))
    {
        printf("\033[0;0H");
        printf("\033[2J");
        retcode = 0;
    }
    else if (!strcmp(argv[0], "cd"))
    {
        if (argc == 1)
        {
            retcode = -EINVAL;
        }
        else
        {
            retcode = chdir(argv[1]);
            if (retcode == -ENOTDIR)
            {
                printf("cd: %s: Not a directory\n", argv[1]);
            }
            else if (retcode < 0)
            {
                printf("cd: %s: No such directory\n", argv[1]);
            }
        }
    }
    else if (!strcmp(argv[0], "exit"))
    {
        exited = true;
        retcode = 0;
    }
    else if (!strcmp(argv[0], "run"))
    {
        if (argc >= 2)
        {
            retcode = run_exec((const char *)argv[1], argv + 1, NULL);
        }
        else
        {
            printf("%s: invalid arguments", argv[0]);
        }
    }
    else if (!strcmp(argv[0], "pwd"))
    {
        char cwd[256];
        getcwd(cwd);
        printf("%s\n", cwd);
    }
    else
    {
        printf("%s: command not found\n", argv[0]);
        retcode = -1;
    }

    for (int i = 0; i < argc; i++)
    {
        free(argv[i]);
    }
    free(argv);

    return retcode;
}

int main()
{
    signal(SIGQUIT, 0);
    signal(SIGWRSZ, (uint64_t)window_resize_handler);

    create_window("shell");

    while (color_map == NULL || width == 0 || height == 0)
    {
        pause();
    }
    memset(color_map, 0xff, width * height * sizeof(uint32_t));

    write_window(0, 0, width, height, color_map);

    path = malloc(1024);
    memset(path, 0, 1024);
    sprintf(path, "/");

    chdir(path);

    pl_readline_t readln = pl_readline_init(getc, putc, flush, handle_tab);

    char prompt[256];
    while (true)
    {
        getcwd(path);
        sprintf(prompt, "\033[1;32mroot\033[m:\033[1;34m%s\033[m# ", path);
        const char *line = pl_readline(readln, prompt);
        printf("\033[m");
        shell_exec(path, line);
        if (exited)
            break;
    }

    pl_readline_uninit(readln);

    return 0;
}
