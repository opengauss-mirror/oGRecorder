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

WR_BIN=wrserver
WR_BIN_FULL=${WR_HOME}/bin/wrserver
WR_BIN_CMD=${WR_HOME}/bin/wrcmd
BIN_PATH=${GAUSSHOME}/bin
SCRIPT_NAME=$0

usage()
{
    echo "Usage: $0 [cmd] [wrserver_id] [DSS_HOME] [GSDB_HOME]"
    echo "cmd:"
    echo "    -start: start wrserver"
    echo "    -stop: stop wrserver"
    echo "    -check: check wrserver"
    echo "    -clean: clean wrserver&${GSDB_BIN}"
    echo "    -reg: register wrserver"
    echo "    -unreg: unregister wrserver"
    echo "    -isreg: check whether wrserver is registered"
    echo "wrserver_id:"
    echo "    wrserver id"
    echo "WR_HOME:"
    echo "    wrserver data path"
    echo "GSDB_HOME:"
}

if [ $# -lt 2 ]
then
    echo  "parameter numbers not meet, num=$#."
    usage
    exit 1
fi

log()
{
   time=`date "+%Y-%m-%d %H:%M:%S"`
   echo "[$time][DSS]$1" >> ${startdss_log} 2>&1
   return
}

assert_empty()
{
    return
}

assert_nonempty()
{
    if [[ -z ${2} ]]
    then
        log "[SCRIPT]The ${1} parameter is empty."
        exit 1
    fi
}

program_pid()
{
    pid=`ps -f f -u \`whoami\` | grep -w ${1} | grep ${2} | grep -v grep | grep -v ${SCRIPT_NAME} | awk '{print $2}' | tail -1`
    echo ${pid}
}

program_pid2()
{
    pid=`ps -f -u \`whoami\` | grep -w ${1} | grep -v grep | grep -v ${SCRIPT_NAME} | awk '{print $2}'`
    result=""
    for p in ${pid}; do
        ppid=`ps -o ppid= -p ${p}`
        parent_name=`ps -p ${ppid} -o comm=`
        if [ "${parent_name}" != "cm_server" ]; then
            result="${result} ${p}"
        fi
    done

    echo ${result}
}

program_status()
{
    pid=`program_pid $1 $2`
    if [[ -z ${pid} ]]; then
        echo ""
        return
    fi

    pstatus_file="/proc/"${pid}"/status"
    cat ${pstatus_file} | while read line
    do
        if [[ "${line}" =~ ^State.* ]]; then
            echo ${line} | awk -F ":" '{print $2}' | awk -F " " '{print $1}'
            return
        fi
    done

    echo ""
}

kill_program()
{
    assert_nonempty 1 ${1}
    assert_nonempty 2 ${2}
    pid=`program_pid $1 $2`
    if [[ -z ${pid} ]]
    then
        log "[KILL]${1} is already dead."
        return
    fi

    kill -9 ${pid}
    if [ $? -ne 0 ]
    then
        log "[KILL]ERROR! ${1} with pid:${pid} is not killed..."
        exit 1
    fi
    for ((i=0; i < 30; i++))
    do
        ps -f -p "${pid}" | grep ${1}
        if [ $? -eq 0 ]
        then
            sleep 0.1
        else
            log "[KILL]SUCCESS!"
            return
        fi
    done

    log "[KILL]ERROR! ${1} with pid:${pid} is not killed..."
    exit 1
}

function check_wr_config()
{
    log "[START]Checking wr_inst.ini before start wr..."
    if [[ ! -e ${WR_HOME}/cfg/wr_inst.ini ]]
    then
        log "[START]${DSS_HOME}/cfg/wr_inst.ini must exist"
        exit 1
    fi
}

function Check()
{
    wr_status=$(program_status wrserver ${WR_HOME})
    if [[ -z ${wr_status} ]]
    then
        log "[CHECK]wrserver is offline."
        exit 1
    fi
    if [[ "${wr_status}" == "D" || "${dss_status}" == "T" || "${wr_status}" == "Z" ]]
    then
        log "[CHECK]wrserver is dead."
        exit 3
    fi
    ${WR_BIN_CMD} getstatus
    wr_status=$?
    if [ ${wr_status} != 0 ]
    then
        log "[CHECK]wrcmd status return code: $wr_status"
        exit 2
    fi
}

CMD=${1}
INSTANCE_ID=${2}
export WR_HOME=${3}
CONN_PATH=UDS:${WR_HOME}/.wr_unix_d_socket
startdss_log=${WR_HOME}/startwr.log

get_startwr_log()
{
    LOG_HOME=`cat ${WR_HOME}/cfg/wr_inst.ini | sed s/[[:space:]]//g |grep -Eo "^LOG_HOME=.*" | awk -F '=' '{print $2}'`
    if [[ ! -z ${LOG_HOME} ]]
    then
        startwr_log=${LOG_HOME}/startwr.log
    fi

    if [[ -z ${WR_HOME} ]]
    then
        startwr_log=/dev/null
    else
        touch_logfile $startwr_log
    fi
}

kill_wr()
{
    pid=$(program_pid wrserver ${WR_HOME})
    if [[ -z ${pid} ]]
    then
        log "[${1}]wrserver not exist."
        echo "wrserver not exist"
    fi
    kill_program wrserver ${DSS_HOME}
    log "[${1}]Success to kill wrserver."
}

# 1st step: if database exists, kill it
# 2nd step: if dssserver no exists, start it
function Start()
{
    pid=`program_pid ${WR_BIN_FULL} ${WR_HOME}`
    if [[ ! -z ${pid} ]]
    then
        log "[START]wrserver already started in dir ${WR_HOME}..."
    else
        log "[START]Starting weserver..."
        log "[START]wrserver"
        #nohup ${WR_BIN_FULL} -D ${WR_HOME} >> ${startwr_log} 2>&1  &
        ${WR_BIN_FULL} -D ${WR_HOME} &
        log "[START]start wrserver in ${WR_HOME} is starting."
    fi
}

kill_program()
{
    assert_nonempty 1 ${1}
    assert_nonempty 2 ${2}
    pid=`program_pid $1 $2`
    if [[ -z ${pid} ]]
    then
        log "${1} is already dead."
        return
    fi

    kill -9 ${pid}
    sleep 3
    ps -f -p "${pid}" | grep ${1}
    if [ $? = 0 ]
    then
        log "ERROR! ${1} with pid:${pid} is not killed..."
        exit 0
    fi
}

function Clean()
{
    kill_program wrserver ${WR_HOME}
}


function Stop()
{
    kill_program wrserver ${WR_HOME}
}

function Main()
{
    if [ "$CMD" == "-start" ]; then
        Start
        exit 0
    elif [ "$CMD" == "-stop" ]; then
        Stop
        exit 0
    elif [ "$CMD" == "-check" ]; then
        Check
        exit 0
    elif [ "$CMD" == "-clean" ]; then
        Clean
        exit 0
    elif [ "$CMD" == "-reg" ]; then
        exit 0
    elif [ "$CMD" == "-unreg" ]; then
        exit 0
    elif [ "$CMD" == "-isreg" ]; then
        exit 11
    else
        echo "[SCRIPT]Please confirm the input parameters."
        exit 1
    fi
}

Main