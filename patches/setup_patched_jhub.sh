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

for f in `ls ${DIR}/patch_files/*.patch`
do
    PATCHNAME=$(basename $f)
    echo $PATCHNAME
    patch -d ${DIR}/${1} -p1 < $f
    # echo "patch -d ${DIR}/${1} -p1 < $f"
done

cp -rp ${DIR}/${1}/jupyterhub ${DIR}/${1}/jupyterhub-patched
