#!/bin/bash

export PATH=${GAUSSHOME}/bin:$PATH
export LD_LIBRARY_PATH=${GAUSSHOME}/lib:${GAUSSHOME}/add-ons:$LD_LIBRARY_PATH

curr_path=`dirname $(readlink -f $0)`
curr_filename=`basename $(readlink -f $0)`
os_user=`whoami`

file_user=`ls -l ${curr_path}"/${curr_filename}" | awk '{print $3}'`

if [ ${file_user} != ${os_user} ]; then
    echo "Can't run ${curr_filename}, because it does not belong to the current user!"
    exit 1
fi

resName=CM-RestAPI
cmdKey=cmrestapi-7.0.0-RC2-RELEASE.jar
phony_dead_time_file=.cmrestapi_phony_dead_time
PHONY_MAX_TIME=20
envFile=$MPPDB_ENV_SEPARATE_PATH
appWhiteListFile=$GAUSSHOME/bin/restWhiteList
cmrestapiPath=$GAUSSHOME/bin/cmrestapi-7.0.0-RC2-RELEASE.jar
LOG_DIR=$GAUSSLOG/cm/cmrestapi
LOG_FILE=$LOG_DIR/cmrestapi.log

SSL_CONFIG_FILE=${SSL_CONFIG_FILE:-$GAUSSHOME/bin/rest_ssl.properties}

if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
fi

function load_ssl_config() {
    if [ ! -f "$SSL_CONFIG_FILE" ]; then
        echo "Warning: SSL config file not found: $SSL_CONFIG_FILE" >&2
        return 1
    fi
    
    SSL_OPTS=""
    while IFS='=' read -r key value || [ -n "$key" ]; do
        key_trimmed=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ "$key_trimmed" =~ ^# ]] && continue
        [[ -z "$key_trimmed" ]] && continue

        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        value=$(echo "$value" | sed "s|\${GAUSSHOME}|$GAUSSHOME|g")

        if [ -n "$key" ]; then
            if [[ "$value" =~ [[:space:]] ]]; then
                SSL_OPTS="$SSL_OPTS -D$key=\"$value\""
            else
                SSL_OPTS="$SSL_OPTS -D$key=$value"
            fi
        fi
    done < "$SSL_CONFIG_FILE"
    
    echo "$SSL_OPTS"
}

function exec_start
{
    ssl_opts=$(load_ssl_config)

    nohup java -jar \
        $ssl_opts \
        $cmrestapiPath \
        -e $envFile \
        -w $appWhiteListFile \
        -g >> $GAUSSLOG/cm/cmrestapi/cmrestapi.log 2>&1 &
    exit $?
}

function exec_stop
{
    ps x | grep "$cmdKey" | grep -v grep | awk '{print $1}' | xargs kill -9; exit $?
}

function exec_check
{
    pid=`ps x | grep "$cmdKey" | grep -v grep | awk '{print $1}'`
    if [ "${pid}" == "" ]; then
        echo "$resName is not running."
        exit 1
    fi
    state=`cat /proc/$pid/status | grep "State" | awk '{print $2}'`
    if [ "$state" == "T" ]; then
        if [ ! -f $phony_dead_time_file ]; then
            touch ./${phony_dead_time_file}
            echo "export firstphonytime=''" > ./${phony_dead_time_file}
        fi
        source ./$phony_dead_time_file;
        curtime=$(date +%s);
        if [ "$firstphonytime" == "" ]; then
            echo "export firstphonytime=$curtime" > ./$phony_dead_time_file;
            exit 0;
        fi
        dead_time=$(( $curtime - $firstphonytime ));
        if [ $dead_time -ge $PHONY_MAX_TIME ]; then
            echo "$resName is detected in a state of phony dead(T) and will be forcibly killed!"
            kill -9 $pid
            rm ./${phony_dead_time_file} -f
            exec_start
        else
            exit 0
        fi
    elif [ "$state" == "S" ]; then
        rm ./${phony_dead_time_file} -f
        echo "$resName is running normally."
        exit 0
    fi
}

if [ $1 == '-start' ]; then
    exec_start $2
elif [ $1 == '-stop' ]; then
    return 0
elif [ $1 == '-check' ]; then
    exec_check $2
elif [ $1 == '-clean' ]; then
    exit 0
elif [ $1 == '-reg' ]; then
    exit 0
elif [ $1 == '-unreg' ]; then
    exit 0
elif [ $1 == '-isreg' ]; then
    exit 11
else
    echo "Please confirm the input parameters."
    exit 1
fi