#!/bin/sh
for f in `ls /src/patches/patch_files/*.patch`
do
    echo "JupyterHub: Apply patch $(basename $f)"
    patch -d /src/ -p1 < $f
done
pip3 install -e /src/jupyterhub
