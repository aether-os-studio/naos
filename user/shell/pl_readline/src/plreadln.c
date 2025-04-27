//
// This file is part of pl_readline.
// pl_readline is free software: you can redistribute it and/or modify
// it under the terms of MIT license.
// See file LICENSE or https://opensource.org/licenses/MIT for full license
// details.
//
// Copyright (c) 2024 min0911_ https://github.com/min0911Y
//

// plreadln.c: 实现pl_readline的核心功能
#include <assert.h>
#include <pl_readline.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pl_readline_add_history(_self, char *line)
{
  list_prepend(self->history, strdup(line));
  return PL_READLINE_SUCCESS;
}

int pl_readline_modify_history(_self)
{
  list_t node = list_nth(self->history, self->history_idx);
  // 当前历史记录肯定不为空，如果为空炸了算了
  free(node->data);
  node->data = strdup(self->buffer);
  return PL_READLINE_SUCCESS;
}

pl_readline_t pl_readline_init(
    int (*pl_readline_hal_getch)(void), void (*pl_readline_hal_putch)(int ch),
    void (*pl_readline_hal_flush)(void),
    void (*pl_readline_get_words)(char *buf, pl_readline_words_t words))
{
  pl_readline_t plreadln = malloc(sizeof(struct pl_readline));
  if (!plreadln)
    return NULL;
  // 设置回调函数
  plreadln->pl_readline_hal_getch = pl_readline_hal_getch;
  plreadln->pl_readline_hal_putch = pl_readline_hal_putch;
  plreadln->pl_readline_hal_flush = pl_readline_hal_flush;
  plreadln->pl_readline_get_words = pl_readline_get_words;
  // 设置history链表
  plreadln->history = NULL;
  plreadln->maxlen = PL_READLINE_DEFAULT_BUFFER_LEN;
  // 设置输入缓冲区
  plreadln->buffer = malloc(plreadln->maxlen);
  plreadln->input_buf = malloc(plreadln->maxlen);
  if (!plreadln->buffer || !plreadln->input_buf)
  {
    pl_readline_uninit(plreadln);
    return NULL;
  }
  pl_readline_add_history(plreadln, "");
  return plreadln;
}

void pl_readline_uninit(_self)
{
  list_free_with(self->history, free);
  free(self->buffer);
  free(self->input_buf);
  free(self);
}

void pl_readline_insert_char(char *str, char ch, int idx)
{
  int len = strlen(str) + 1; // 还要复制字符串结束符
  if (len)
    memmove(str + idx + 1, str + idx, len - idx);
  str[idx] = ch;
}

static void pl_readline_delete_char(char *str, int idx)
{
  int len = strlen(str);
  if (len)
    memmove(str + idx, str + idx + 1, len - idx);
  str[len] = '\0';
}

void pl_readline_print(_self, char *str)
{
  while (*str)
  {
    self->pl_readline_hal_putch(*str++);
  }
}

static void pl_readline_reset(_self, int p, int len)
{
  char buf[255] = {0};
  if (p)
  {
    sprintf(buf, "\033[%dD", p);
    pl_readline_print(self, buf);
  }
  if (len)
  {
    for (int i = 0; i < len; i++)
    {
      self->pl_readline_hal_putch(' ');
    }
    sprintf(buf, "\033[%dD", len);
    pl_readline_print(self, buf);
  }
}

static void pl_readline_to_the_end(_self, int n)
{
  char buf[255] = {0};
  sprintf(buf, "\033[%dC", n);
  pl_readline_print(self, buf);
}

// 处理向上向下键（移动到第n个历史）
static bool pl_readline_handle_history(_self, int n)
{
  list_t node = list_nth(self->history, n); // 获取历史记录
  if (!node)
    return false;
  pl_readline_reset(self, self->ptr, self->length); // 重置光标和输入的字符
  self->pl_readline_hal_flush();                    // 刷新输出缓冲区，在Linux下需要,否则会导致输入不显示
  self->ptr = 0;                                    // 光标移动到最左边
  self->length = 0;                                 // 清空缓冲区长度
  memset(self->buffer, 0, self->maxlen);            // 清空缓冲区
  strcpy(self->buffer, node->data);
  pl_readline_print(self, self->buffer); // 打印历史记录
  self->length = strlen(self->buffer);   // 更新缓冲区长度
  self->ptr = self->length;

  memset(self->input_buf, 0, self->maxlen); // 清空输入缓冲区
  self->input_ptr = 0;                      // 输入缓冲区指针置0
  char *p = node->data;
  while (*p)
  {
    if (*p == ' ')
    {
      self->input_ptr = 0;
      p++;
      continue;
    }
    self->input_buf[self->input_ptr++] = *p++;
  }
  self->input_buf[self->input_ptr] = '\0';
  self->input_ptr = strlen(self->input_buf); // 更新输入缓冲区指针
  return true;
}

void pl_readline_insert_char_and_view(_self, char ch)
{
  if (self->length >= self->maxlen)
  {
    self->maxlen *= 2;
    self->buffer = realloc(self->buffer, self->maxlen);
    self->input_buf = realloc(self->input_buf, self->maxlen);
    self->buffer[self->length] = '\0';
    if (!self->buffer)
      abort(); // 炸了算了
  }
  pl_readline_insert_char(self->buffer, ch, self->ptr++);
  self->length++;
  int n = self->length - self->ptr;
  if (n)
  {
    char buf[255] = {0};
    pl_readline_print(self, self->buffer + self->ptr - 1);
    sprintf(buf, "\033[%dD", n);
    pl_readline_print(self, buf);
  }
  else
  {
    self->pl_readline_hal_putch(ch);
  }
}

void pl_readline_next_line(_self)
{
  int n = self->length - self->ptr;
  char buf[255] = {0};
  if (!n)
  {
    pl_readline_print(self, "\n");
    return;
  }
  sprintf(buf, "\033[%dC", n); // 光标移动到最右边
  pl_readline_print(self, buf);
  pl_readline_print(self, "\n");
}

// 处理输入的字符
int pl_readline_handle_key(_self, int ch)
{
  if (ch != PL_READLINE_KEY_TAB)
  {
    self->intellisense_mode = false;
    if (self->intellisense_word)
    {
      free(self->intellisense_word);
      self->intellisense_word = NULL;
    }
  }
  if (self->length >= self->maxlen)
  {
    self->maxlen *= 2;
    self->buffer = realloc(self->buffer, self->maxlen);
    self->input_buf = realloc(self->input_buf, self->maxlen);
    self->buffer[self->length] = '\0'; // input_buf在处理时会自动截断 不用我们加
    if (!self->buffer)
      return PL_READLINE_FAILED;
  }
  switch (ch)
  {
  case PL_READLINE_KEY_DOWN:
    pl_readline_modify_history(self);
    if (pl_readline_handle_history(self, self->history_idx - 1))
      self->history_idx--;
    break;
  case PL_READLINE_KEY_UP:
  {
    pl_readline_modify_history(self);
    if (pl_readline_handle_history(self, self->history_idx + 1))
      self->history_idx++;
    break;
  }
  case PL_READLINE_KEY_LEFT:
    if (!self->ptr) // 光标在最左边
      return PL_READLINE_NOT_FINISHED;
    self->ptr--;
    pl_readline_print(self, "\033[D");
    if (self->buffer[self->ptr] == ' ')
    {
      memset(self->input_buf, 0, self->maxlen);
      // 光标移动到前一个空格
      size_t i = self->ptr;
      while (i && self->buffer[i - 1] != ' ')
      {
        i--;
      }
      self->input_ptr = 0;
      // 从i开始复制到self->input_buf，直到遇到空格
      while (i < self->ptr && self->buffer[i] != ' ')
      {
        self->input_buf[self->input_ptr++] = self->buffer[i];
        i++;
      }
      // 字符串结束符号
      self->input_buf[self->input_ptr] = '\0';
    }
    else
    {
      self->input_ptr--;
    }
    break;
  case PL_READLINE_KEY_RIGHT:
    if (self->ptr == self->length) // 光标在最右边
      return PL_READLINE_NOT_FINISHED;
    self->ptr++;
    pl_readline_print(self, "\033[C");
    if (self->buffer[self->ptr - 1] == ' ')
    {
      memset(self->input_buf, 0, self->maxlen);
      // 光标移动到前一个空格
      size_t i = self->ptr;
      size_t j = i;
      while (i < self->length && self->buffer[i + 1] != ' ')
      {
        i++;
      }
      self->input_ptr = 0;
      // 从i开始复制到self->input_buf，直到遇到空格
      while (j <= i && self->buffer[i] != ' ')
      {
        self->input_buf[self->input_ptr++] = self->buffer[j];
        j++;
      }
      // 字符串结束符号
      self->input_buf[self->input_ptr] = '\0';
      self->input_ptr = 0;
    }
    else
    {
      self->input_ptr++;
    }
    break;
  case PL_READLINE_KEY_BACKSPACE:
    if (!self->ptr) // 光标在最左边
      return PL_READLINE_NOT_FINISHED;
    --self->ptr;
    if (self->buffer[self->ptr] == ' ')
    {
      memset(self->input_buf, 0, self->maxlen);
      // 光标移动到前一个空格
      size_t i = self->ptr;
      while (i && self->buffer[i - 1] != ' ')
      {
        i--;
      }
      self->input_ptr = 0;
      // 从i开始复制到self->input_buf，直到遇到空格
      while (i < self->ptr && self->buffer[i] != ' ')
      {
        self->input_buf[self->input_ptr++] = self->buffer[i];
        i++;
      }
      // 字符串结束符号
      self->input_buf[self->input_ptr] = '\0';
    }
    else
    {
      if (self->input_ptr)
        pl_readline_delete_char(self->input_buf, --self->input_ptr);
    }
    pl_readline_delete_char(self->buffer, self->ptr);

    self->length--;

    int n = self->length - self->ptr;
    if (n)
    {
      char buf[255] = {0};
      sprintf(buf, "\033[%dC\033[D ", n);
      pl_readline_print(self, buf);

      sprintf(buf, "\033[%dD", n);
      pl_readline_print(self, buf);
      pl_readline_print(self, "\033[D");
      pl_readline_print(self, self->buffer + self->ptr);
      pl_readline_print(self, buf);
    }
    else
    {
      pl_readline_print(self, "\b \b");
    }
    break;
  case PL_READLINE_KEY_ENTER:
    pl_readline_to_the_end(self, self->length - self->ptr);
    self->pl_readline_hal_putch('\n');
    self->buffer[self->length] = '\0';
    self->history_idx = 0;
    pl_readline_modify_history(self);
    if (self->buffer[0] != '\0')
    {
      pl_readline_add_history(self, "");
    }
    return PL_READLINE_SUCCESS;
  case PL_READLINE_KEY_TAB:
  { // 自动补全
    pl_readline_words_t words = pl_readline_word_maker_init();
    pl_readline_word word_seletion = pl_readline_intellisense(self, words);
    if (word_seletion.word)
    {
      pl_readline_intellisense_insert(self, word_seletion);
      self->pl_readline_hal_flush();
    }
    else if (word_seletion.first)
    {
      pl_readline_print(self, "\n");
      pl_readline_print(self, self->prompt);
      self->buffer[self->length] = '\0';
      pl_readline_print(self, self->buffer);
      int n = self->length - self->ptr;
      char buf[255] = {0};
      if (n)
      {
        sprintf(buf, "\033[%dD", n);
        pl_readline_print(self, buf);
      }
      self->pl_readline_hal_flush();
    }
    break;
  }
  case PL_READLINE_KEY_CTRL_A:
  case PL_READLINE_KEY_HOME:
    pl_readline_reset(self, self->ptr, 0);
    self->ptr = 0;
    break;
  case PL_READLINE_KEY_END:
  {
    size_t diff = self->length - self->ptr;
    if (diff)
    {
      pl_readline_to_the_end(self, self->length - self->ptr);
      self->ptr = self->length;
    }
    break;
  }
  case PL_READLINE_KEY_PAGE_UP:
  {
    size_t len = list_length(self->history);
    pl_readline_modify_history(self);
    pl_readline_handle_history(self, len - 1);
    self->history_idx = len - 1;
    break;
  }
  case PL_READLINE_KEY_PAGE_DOWN:
    pl_readline_modify_history(self);
    pl_readline_handle_history(self, 0);
    self->history_idx = 0;
    break;
  case PL_READLINE_KEY_CTRL_C:
    self->buffer[0] = '\0';
    pl_readline_print(self, "^C\n");
    return PL_READLINE_SUCCESS;
  case ' ':
  {
    memset(self->input_buf, 0, self->maxlen);
    self->input_ptr = 0;
    goto handle;
  }
  default:
  {
    pl_readline_insert_char(self->input_buf, ch, self->input_ptr++);
  handle:
    pl_readline_insert_char_and_view(self, ch);
    break;
  }
  }
  return PL_READLINE_NOT_FINISHED;
}

// 主体函数
const char *pl_readline(_self, char *prompt)
{
  // 清空运行时状态
  memset(self->buffer, 0, self->maxlen);
  memset(self->input_buf, 0, self->maxlen);
  self->input_ptr = 0;
  self->ptr = 0;
  self->length = 0;
  self->history_idx = 0;
  self->prompt = prompt;
  self->intellisense_mode = false;
  self->intellisense_word = NULL;

  // 打印提示符
  pl_readline_print(self, prompt);
  // 刷新输出缓冲区，在Linux下需要,否则会导致输入不显示
  self->pl_readline_hal_flush();

  // 循环读取输入
  while (true)
  {
    int ch = self->pl_readline_hal_getch(); // 读取输入
    int status = pl_readline_handle_key(self, ch);
    if (status == PL_READLINE_SUCCESS)
    {
      break;
    }
  }

  if (self->intellisense_word)
  {
    free(self->intellisense_word);
  }

  return self->buffer;
}
