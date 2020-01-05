#/bin/bash

ROOT_DIR="/home/ed/SlackBotServer"
pid=$(ps aux | grep python| grep  server.py | grep -v sudo | grep -v grep | awk '{ print $2 }')
if test -n "$pid"; then
  sudo kill $pid
fi
sleep 1
echo '--------' $(date) '-------' >> ${ROOT_DIR}/log/server.log
sudo ${ROOT_DIR}/bin/python ${ROOT_DIR}/src/server.py >> ${ROOT_DIR}/log/server.log 2>&1 &
