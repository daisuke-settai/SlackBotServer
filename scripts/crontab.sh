#/bin/bash

ROOT_DIR="/home/ed/SlackBotServer"
echo '--------' $(date) '-------' >> ${ROOT_DIR}/log/cron_job.log
sudo ${ROOT_DIR}/bin/python ${ROOT_DIR}/src/cron_job.py >> ${ROOT_DIR}/log/cron_job.log 2>&1 &
