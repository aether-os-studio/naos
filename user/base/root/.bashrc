#! /bin/sh
#
# System wide environment variables and startup programs should go into
# /etc/profile.  Personal environment variables and startup programs
# should go into ~/.bash_profile.  Personal aliases and functions should
# go into ~/.bashrc

# Provides colored /bin/ls and /bin/grep commands.  Used in conjunction
# with code in /etc/profile.
source /etc/profile

# Only if nothing has already set it (like a terminal emulator)
if [ -z "${TERM}" ] || [ "${TERM}" == "dumb" ]; then
	export TERM=linux
fi

export PATH="/bin:/usr/bin:/usr/sbin:/sbin:/bin:/usr/local/bin:/usr/local/sbin"
export LANG=en_US.UTF-8
export LIBGL_ALWAYS_SOFTWARE=1
export SHELL=/bin/bash
export HOME="/root"

export SDL_AUDIODRIVER=dummy

export XDG_RUNTIME_DIR=/run
export XDG_CONFIG_HOME=$HOME/.config

NORMAL="\[\e[0m\]"
RED="\[\e[1;31m\]"
GREEN="\[\e[1;32m\]"
if [[ $EUID == 0 ]]; then
  	PS1="$RED\u@\h [ $NORMAL\w$RED ]# $NORMAL"
else
  	PS1="$GREEN\u@\h [ $NORMAL\w$GREEN ]\$ $NORMAL"
fi

unset RED GREEN NORMAL

alias ls='ls --color=auto'
alias grep='grep --color=auto'
