#!/bin/bash

# Variables used for git clone commands
SHARE_BASE_DIR="/tmp/share_base"
SHARE_OVERLAYS_DIR="/tmp/share_overlays"
SHARE_BLOCKLIST_DIR="/tmp/share_blocklist"

# Prepare base + overlays in this directory, before moving it to /mnt/shared-data
SHARE_COPY_DIR="/tmp/share_copy"

# In this directory JupyterHub will look for the template files
SHARE_DIR="/mnt/shared-data/share"
SHARE_JHUB_DIR="/mnt/shared-data/share/jupyterhub"
mkdir -p ${SHARE_JHUB_DIR}

# In this directory nginx will look for the static files
SHARE_NGINX_DIR="/mnt/shared-data/static-files"
mkdir -p ${SHARE_NGINX_DIR}

# In this directory Jupyterhub will look for the blocklist files
SHARE_JHUB_BLOCKLIST="/mnt/shared-data/blocklist"
mkdir -p ${SHARE_JHUB_BLOCKLIST}

# create temporary folders
mkdir -p $(dirname ${SHARE_BASE_DIR})
mkdir -p $(dirname ${SHARE_BLOCKLIST_DIR})

if [[ -e ${SHARE_BASE_DIR} ]]; then
    rm -rf ${SHARE_BASE_DIR}
fi

if [[ -e ${SHARE_BLOCKLIST_DIR} ]]; then
    rm -rf ${SHARE_BLOCKLIST_DIR}
fi

cd $(dirname ${SHARE_BASE_DIR})
if [[ -n ${SHARE_BASE_GIT_USERNAME} &&  -n ${SHARE_BASE_GIT_PASSWORD} ]]; then
    git clone --single-branch --branch ${SHARE_BASE_GIT_BRANCH} https://${SHARE_BASE_GIT_USERNAME}:${SHARE_BASE_GIT_PASSWORD}@${SHARE_BASE_GIT_REPO#"https://"} $(basename ${SHARE_BASE_DIR})
else
    git clone --single-branch --branch ${SHARE_BASE_GIT_BRANCH} https://${SHARE_BASE_GIT_REPO#"https://"} $(basename ${SHARE_BASE_DIR})
fi

cd $(dirname ${SHARE_BLOCKLIST_DIR})
if [[ -n ${GIT_BLOCKLIST_USERNAME} && -n ${GIT_BLOCKLIST_PASSWORD} ]]; then
    git clone --single-branch --branch ${GIT_BLOCKLIST_BRANCH} https://${GIT_BLOCKLIST_USERNAME}:${GIT_BLOCKLIST_PASSWORD}@${GIT_BLOCKLIST_REPO#"https://"} $(basename ${SHARE_BLOCKLIST_DIR})
else
    git clone --single-branch --branch ${GIT_BLOCKLIST_BRANCH} ${GIT_BLOCKLIST_REPO} $(basename ${SHARE_BLOCKLIST_DIR})
fi

if [[ -n ${SHARE_OVERLAYS_GIT_REPO} ]]; then
    mkdir -p $(dirname ${SHARE_OVERLAYS_DIR})

    if [[ -e ${SHARE_OVERLAYS_DIR} ]]; then
        rm -rf ${SHARE_OVERLAYS_DIR}
    fi

    cd $(dirname ${SHARE_OVERLAYS_DIR})
    if [[ -n ${SHARE_OVERLAYS_GIT_USERNAME} && -n ${SHARE_OVERLAYS_GIT_PASSWORD} ]]; then
        git clone --single-branch --branch ${SHARE_OVERLAYS_GIT_BRANCH} https://${SHARE_OVERLAYS_GIT_USERNAME}:${SHARE_OVERLAYS_GIT_PASSWORD}@${SHARE_OVERLAYS_GIT_REPO#"https://"} $(basename ${SHARE_OVERLAYS_DIR})
    else
        git clone --single-branch --branch ${SHARE_OVERLAYS_GIT_BRANCH} ${SHARE_OVERLAYS_GIT_REPO} $(basename ${SHARE_OVERLAYS_DIR})
    fi
fi

git config --global pull.ff only


update() {
  echo "$(date) - Check for updates in templates and static files"

  if [[ ${1} == "force" ]]; then
      FORCE=1
  else
      FORCE=0
  fi

  # Check if base templates got an update

  check_git_update() {
      # Check for changes on remote origin
      cd ${1}
      git fetch -q
      test "$(git rev-parse HEAD)" == "$(git rev-parse @{u})"
      echo $?
  }

  SHARE_BASE_UPDATED=$(check_git_update ${SHARE_BASE_DIR})
  if [[ -n ${SHARE_OVERLAYS_GIT_REPO} ]]; then
      SHARE_OVERLAYS_UPDATED=$(check_git_update ${SHARE_OVERLAYS_DIR})
  else
      SHARE_OVERLAYS_UPDATED=0
  fi

  # If one was updated, we have to prepare a new directory
  if [[ ${SHARE_BASE_UPDATED} -eq 1 || ${SHARE_OVERLAYS_UPDATED} -eq 1 || ${FORCE} -eq 1 ]]; then
      echo "$(date) - Shared files update (Base: ${SHARE_BASE_UPDATED} , Overlays: ${SHARE_OVERLAYS_UPDATED}, Force ${FORCE})"
      mkdir -p ${SHARE_COPY_DIR}
      cd ${SHARE_BASE_DIR}
      git pull origin ${SHARE_BASE_GIT_BRANCH}
      cp -r ${SHARE_BASE_DIR}/* ${SHARE_COPY_DIR}/.

      if [[ -n ${SHARE_OVERLAYS_GIT_REPO} ]]; then
          cd ${SHARE_OVERLAYS_DIR}
          git pull origin ${SHARE_OVERLAYS_GIT_BRANCH}

          copy_overlays_subdir() {
              if [[ -d ${SHARE_OVERLAYS_DIR}/${1} ]]; then
                  if [[ ! -d ${SHARE_COPY_DIR}/${1} ]]; then
                      mkdir -p ${SHARE_COPY_DIR}/${1}
                  fi
                  cp -r ${SHARE_OVERLAYS_DIR}/${1}/* ${SHARE_COPY_DIR}/${1}/.
              fi
          }
          copy_overlays_subdir templates
          copy_overlays_subdir static

      fi
      # Remove footer.systems images. These are managed by check_incidents in antoher script.
      if [[ -d ${SHARE_COPY_DIR}/static/images/footer/systems ]]; then
          rm -r ${SHARE_COPY_DIR}/static/images/footer/systems/*
      fi

      chown -R 1000:100 ${SHARE_COPY_DIR}
      cp -r ${SHARE_COPY_DIR}/* ${SHARE_JHUB_DIR}/.
      cp -r ${SHARE_COPY_DIR}/static/* ${SHARE_NGINX_DIR}/.
      chown -R 1000:100 ${SHARE_DIR}
      chown -R 1000:100 ${SHARE_NGINX_DIR}
      rm -rf ${SHARE_COPY_DIR}
  fi

  SHARE_BLOCKLIST_UPDATED=$(check_git_update ${SHARE_BLOCKLIST_DIR})

  if [[ ${SHARE_BLOCKLIST_UPDATED} -eq 1 || ${FORCE} -eq 1 ]]; then
      echo "$(date) - Blocklist update detected"
      cd ${SHARE_BLOCKLIST_DIR}
      git pull origin ${GIT_BLOCKLIST_BRANCH}
      cp -r ${SHARE_BLOCKLIST_DIR}/* ${SHARE_JHUB_BLOCKLIST}/.
  fi
}

update force

if [[ ! ${1} == "once" ]]; then
    while true; do
        sleep 60
        update
    done
fi
