#!/bin/bash

if [[ -z ${1} ]]; then
    echo "Argument (JupyterHub version) required. Run 'bash setup_patched_jhub.sh 2.1.1' to download JupyterHub Version 2.1.1"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
mkdir -p ${DIR}/${1}
if [[ -d ${DIR}/${1}/jupyterhub ]]; then
    echo "Folder jupyterhub in patches/${1} already exists. Stop"
    exit 1
fi
if [[ -d ${DIR}/${1}/jupyterhub-patched ]]; then
    echo "Folder jupyterhub-patched in patches/${1} already exists. Stop"
    exit 1
fi
git clone -b ${1} https://github.com/jupyterhub/jupyterhub.git ${DIR}/${1}/jupyterhub

cp -rp ${DIR}/${1}/jupyterhub ${DIR}/${1}/jupyterhub-patched
mkdir ${DIR}/${1}/patch_files
cp ${DIR}/create_patch_file.sh ${DIR}/${1}/.
