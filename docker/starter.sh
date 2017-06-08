#!/bin/bash

catalina.sh run &

apache2 -D FOREGROUND &

/usr/sbin/sshd -D

exit 0
