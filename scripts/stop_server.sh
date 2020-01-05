#/bin/bash

pid=$(ps aux | grep python | grep  server.py | grep -v sudo | grep -v grep | awk '{ print $2 }')
if test -n "$pid"; then
  sudo kill $pid
fi
