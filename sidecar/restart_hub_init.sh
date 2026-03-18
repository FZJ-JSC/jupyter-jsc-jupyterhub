#!/bin/bash
cd /mnt/shared-data
export GIT_REPO_SHORT=${GIT_REPO#"https://"}
if [[ -n ${GIT_USERNAME} && -n ${GIT_PASSWORD} ]]; then
    git clone --single-branch --branch ${GIT_BRANCH:-main} https://${GIT_USERNAME}:${GIT_PASSWORD}@${GIT_REPO_SHORT} static-files
else
    git clone --single-branch --branch ${GIT_BRANCH:-main} https://${GIT_REPO_SHORT} static-files
fi