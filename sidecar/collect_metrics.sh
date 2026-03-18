#!/bin/bash
git config --global user.email "cronjob@fz-juelich.de"
git config --global user.name "CronJob"
git clone --single-branch --branch ${GIT_BRANCH} https://${GIT_TOKEN_NAME}:${GIT_TOKEN}@${GIT_REPO} /tmp/git_repo
cd /tmp/git_repo

if [[ -n ${GIT_SUBDIR} ]]; then
    if [[ ! -d ${GIT_SUBDIR} ]]; then
    mkdir ${GIT_SUBDIR}
    fi
    cd ${GIT_SUBDIR}
fi

git add .
YESTERDAY=$(date -d "1 days ago" +'%Y-%m-%d')
ACTIVE_USER=$(psql -t --csv --command "SELECT COUNT(id) FROM users WHERE last_activity >= '${YESTERDAY} 00:00:00.000000';"  postgresql://${SQL_USER}:${SQL_PASSWORD}@${SQL_HOST}:${SQL_PORT}/${SQL_DATABASE})
echo "${YESTERDAY},${ACTIVE_USER}" >> user_metrics_last_1_days.csv
git add user_metrics_last_1_days.csv

DAYS7=$(date -d "7 days ago" +'%Y-%m-%d')
ACTIVE_USER=$(psql -t --csv --command "SELECT COUNT(id) FROM users WHERE last_activity >= '${DAYS7} 00:00:00.000000';"  postgresql://${SQL_USER}:${SQL_PASSWORD}@${SQL_HOST}:${SQL_PORT}/${SQL_DATABASE})
echo "${YESTERDAY},${ACTIVE_USER}" >> user_metrics_last_7_days.csv
git add user_metrics_last_7_days.csv

DAYS30=$(date -d "30 days ago" +'%Y-%m-%d')
ACTIVE_USER=$(psql -t --csv --command "SELECT COUNT(id) FROM users WHERE last_activity >= '${DAYS30} 00:00:00.000000';"  postgresql://${SQL_USER}:${SQL_PASSWORD}@${SQL_HOST}:${SQL_PORT}/${SQL_DATABASE})
echo "${YESTERDAY},${ACTIVE_USER}" >> user_metrics_last_30_days.csv
git add user_metrics_last_30_days.csv

git commit -m "update metrics"
git push origin ${GIT_BRANCH}
