#/bin/bash

ROOT_DIR="${HOME}/SlackBotServer"
echo '--------' $(date) '-------' >> ${ROOT_DIR}/log/server.log
sudo ${ROOT_DIR}/bin/python ${ROOT_DIR}/src/server.py >> ${ROOT_DIR}/log/server.log 2>&1 &
