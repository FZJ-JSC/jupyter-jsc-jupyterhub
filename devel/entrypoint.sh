#!/bin/bash
export PYTHONPATH=${PYTHONPATH}:/src/jupyterhub:/src/jupyterhub-custom

USERNAME=jovyan

mkdir -p /home/${USERNAME}/.ssh
chown -R ${USERNAME}:users /home/${USERNAME}/.ssh

sed -i -r -e "s/^#PasswordAuthentication yes/PasswordAuthentication no/g" -e "s/^AllowTcpForwarding no/AllowTcpForwarding yes/g" -e "s/^#Port 22/Port 2222/g" /etc/ssh/sshd_config
mkdir -p /run/sshd
/usr/sbin/sshd -f /etc/ssh/sshd_config -E /home/${USERNAME}/sshd.log

mkdir -p /home/${USERNAME}/.vscode
chown -R ${USERNAME}:users /home/${USERNAME}/.vscode

cp -rp /src/jupyterhub /src/jupyterhub-patched
/usr/local/bin/pip3 install -e /src/jupyterhub-patched/
# dev-requirements comes from vanilla JHub
/usr/local/bin/pip3 install -r /src/jupyterhub/requirements.txt

ln -s /src/jupyterhub-patched /home/${USERNAME}/jupyterhub-patched
ln -s /src/jupyterhub-custom /home/${USERNAME}/jupyterhub-custom
ln -s /src/jupyterhub-static /home/${USERNAME}/jupyterhub-static

mkdir -p /home/${USERNAME}/jupyterhub-config/secret
mkdir -p /home/${USERNAME}/jupyterhub-config/config
cp -r /usr/local/etc/jupyterhub/jupyterhub_config.py /home/${USERNAME}/jupyterhub-config/.
cp -r /usr/local/etc/jupyterhub/z2jh.py /home/${USERNAME}/jupyterhub-config/.
cp -r /usr/local/etc/jupyterhub/secret/..data/* /home/${USERNAME}/jupyterhub-config/secret/.
cp -r /usr/local/etc/jupyterhub/config/..data/* /home/${USERNAME}/jupyterhub-config/config/.
sed -i -e 's@/usr/local/etc/jupyterhub@/home/${USERNAME}/jupyterhub-config@g' /home/${USERNAME}/jupyterhub-config/*


chown -R ${USERNAME}:users /home/${USERNAME}
while true; do
    sleep 30
done
