# Patch JupyterHub
This folder will be used to create multiple patches.  
To create a patch run the following commands:  
  
```  
cd patches
bash setup_patched_jhub.sh <JUPYTERHUB_VERSION>
# Now you can edit jupyterhub-patched to overwrite the previously patched JupyterHub code
# Run create_patch_file.sh to apply your changes with a .patch file (suffix .patch in <PATCH_NAME> is NOT required)
bash create_patch_file.sh <JUPYTERHUB_VERSION> <PATCH_NAME>
# patches/jupyterhub will be patched with your new created patch
```
  
