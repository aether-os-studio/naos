#! /bin/bash

weston --tty 1 &
sleep 5
export WAYLAND_DISPLAY=wayland-0
weston-terminal
