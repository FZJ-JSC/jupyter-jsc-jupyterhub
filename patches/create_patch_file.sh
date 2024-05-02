#!/bin/bash


if [[ -z ${1} ]]; then
    echo "Argument (name of patch) required. Will be used in patch file name: xyz_<name>.patch"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ ! -d ${DIR}/patch_files ]]; then
    mkdir -p ${DIR}/patch_files
fi

NUMBER_OF_FILES=`ls ${DIR}/patch_files | wc -l | sed 's/ //g'`
if [[ $NUMBER_OF_FILES -lt 10 ]]; then
    PATCH_PREFIX="00${NUMBER_OF_FILES}_"
elif [[ $NUMBER_OF_FILES -lt 100 ]]; then
    PATCH_PREFIX="0${NUMBER_OF_FILES}_"
else
    PATCH_PREFIX="${NUMBER_OF_FILES}_"
fi

if [[ ${1} == *.patch ]]; then
    PATCH_FILENAME=${1}
else
    PATCH_FILENAME="${1}.patch"
fi

echo "Create patch file patches/patch_files/${PATCH_PREFIX}${PATCH_FILENAME}"
cd ${DIR}/patch_files && diff -Naurx .git -x node_modules -x share -x __pycache__ ../jupyterhub/jupyterhub ../jupyterhub-patched/jupyterhub > ${DIR}/patch_files/${PATCH_PREFIX}${PATCH_FILENAME}

patch -d ${DIR} -p1 < ${DIR}/patch_files/${PATCH_PREFIX}${PATCH_FILENAME}
