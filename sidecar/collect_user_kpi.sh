#!/bin/bash

git config --global user.email "cronjob@fz-juelich.de"
git config --global user.name "CronJob"
git clone --single-branch --branch ${GIT_BRANCH} https://${GIT_TOKEN_NAME}:${GIT_TOKEN}@${GIT_REPO} /tmp/git_repo
cd /tmp/git_repo

if [[ -n ${GIT_SUBDIR} ]]; then
    if [[ ! -d ${GIT_SUBDIR} ]]; then
    mkdir ${GIT_SUBDIR}
    fi
    cd ${GIT_SUBDIR}
fi

git add .

declare -A centres=(
    ["fz-juelich.de"]="FZJ"
    ["awi.de"]="AWI"
    ["cispa.de"]="CISPA"
    ["desy.de"]="DESY"
    ["dkfz-heidelberg.de"]="DKFZ"
    ["dlr.de"]="DLR"
    ["dzne.de"]="DZNE"
    ["geomar.de"]="GEOMAR"
    ["gfz-potsdam.de"]="GFZ"
    ["gsi.de"]="GSI"
    ["hereon.de"]="Hereon"
    ["helmholtz-muenchen.de"]="HMGU"
    ["helmholtz-munich.de"]="HMGU"
    ["helmholtz-berlin.de"]="HZB"
    ["hzdr.de"]="HZDR"
    ["helmholtz-hzi.de"]="HZI"
    ["kit.edu"]="KIT"
    ["mdc-berlin.de"]="MDC"
    ["ufz.de"]="UFZ"
)
org_total=0
org_helmholtz=0
helmholtz=0
others=0
total=0
declare -A counter=(
    ["FZJ"]=0
    ["AWI"]=0
    ["CISPA"]=0
    ["DESY"]=0
    ["DKFZ"]=0
    ["DLR"]=0
    ["DZNE"]=0
    ["GEOMAR"]=0
    ["GFZ"]=0
    ["GSI"]=0
    ["Hereon"]=0
    ["HMGU"]=0
    ["HZB"]=0
    ["HZDR"]=0
    ["HZI"]=0
    ["KIT"]=0
    ["MDC"]=0
    ["UFZ"]=0
)
DATA=$(psql -t --csv --command "SELECT SUBSTRING (name, POSITION('_at_' IN name)+4) as domain, COUNT(SUBSTRING (name, POSITION('_at_' IN name)+4)) FROM users GROUP by domain;" postgresql://${SQL_USER}:${SQL_PASSWORD}@${SQL_HOST}:${SQL_PORT}/${SQL_DATABASE})

YESTERDAY=$(date -d "1 days ago" +'%Y-%m-%d')
neu=$(psql -t --csv --command "SELECT COUNT(id) FROM users WHERE created >= '${YESTERDAY} 00:00:00.000000';" postgresql://${SQL_USER}:${SQL_PASSWORD}@${SQL_HOST}:${SQL_PORT}/${SQL_DATABASE})

while IFS=',' read -r domain count; do
    ((total+=count))
    ((org_total++))
    is_helmholtz=0
    for key in "${!centres[@]}"; do
        # Check if the domain ends with the current key
        if [[ $domain == *"$key" ]]; then
            # Increment the counter for the corresponding centre
            centre=${centres[$key]}
            ((counter["$centre"]+=count))
            ((helmholtz+=count))
            is_helmholtz=1
            break
        fi
    done
    if [[ $is_helmholtz -eq 0 ]]; then
        ((others+=count))
    fi
done <<< "$DATA"

for key in "${!counter[@]}"; do
    if [[ ${counter[$key]} -ne 0 ]]; then
        ((org_helmholtz++))
    fi
done

deprovisioned=0
if [[ ! -f data.csv ]]; then
    echo "#date-time UTC,Accounts total,Accounts Helmholtz,Accounts new,Deprovisioned accounts,Domains total,Organisations Helmholtz,FZJ,AWI,CISPA,DESY,DKFZ,DLR,DZNE,GEOMAR,GFZ,GSI,Hereon,HMGU,HZB,HZDR,HZI,KIT,MDC,UFZ,Comment" >> data.csv
    echo "#plot,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0" >> data.csv
    echo "#unit,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,Number,N/A" >> data.csv
fi
t=$(date +'%Y-%m-%dT%H:%M:%S.%N')
echo "$t,$total,$helmholtz,$neu,$deprovisioned,$org_total,$org_helmholtz,${counter[FZJ]},${counter[AWI]},${counter[CISPA]},${counter[DESY]},${counter[DKFZ]},${counter[DLR]},${counter[DZNE]},${counter[GEOMAR]},${counter[GFZ]},${counter[GSI]},${counter[Hereon]},${counter[HMGU]},${counter[HZB]},${counter[HZDR]},${counter[HZI]},${counter[KIT]},${counter[MDC]},${counter[UFZ]}," >> data.csv
git add data.csv

git commit -m "Update KPIs"
git push origin ${GIT_BRANCH}
