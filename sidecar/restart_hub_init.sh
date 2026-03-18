#!/bin/bash
cd /mnt/shared-data ;
export GIT_REPO_SHORT=${GIT_REPO#"https://"} ; 
git clone --single-branch --branch ${GIT_BRANCH} https://${GIT_USERNAME}:${GIT_PASSWORD}@${GIT_REPO_SHORT} static-files 