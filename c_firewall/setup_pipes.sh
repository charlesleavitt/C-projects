#!/bin/bash

#sets up named pipes for the firewalls to communicate.

mkfifo ToFirewall
mkfifo FromFirewall

