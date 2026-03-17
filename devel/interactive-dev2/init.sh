chown -R jovyan:users /usr/local/lib/python3.12/site-packages/jsc_custom
chown -R jovyan:users /usr/local/lib/python3.12/site-packages/outpostspawner
chown -R jovyan:users /usr/local/lib/python3.12/site-packages/forwardbasespawner
chown -R jovyan:users /usr/local/lib/python3.12/site-packages/unicorespawner
ln -s /usr/local/lib/python3.12/site-packages/jsc_custom /home/jovyan/.
ln -s /usr/local/lib/python3.12/site-packages/outpostspawner /home/jovyan/.
ln -s /usr/local/lib/python3.12/site-packages/forwardbasespawner /home/jovyan/.
ln -s /usr/local/lib/python3.12/site-packages/unicorespawner /home/jovyan/.
cp /mnt/custom-config/..data/jupyterhub_custom_config.yaml /home/jovyan/.
chown -R jovyan:users /home/jovyan
