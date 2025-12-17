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

GR_BIN=grserver
GR_BIN_FULL=${GAUSSHOME}/bin/grserver
GR_BIN_CMD=${GAUSSHOME}/bin/grcmd
BIN_PATH=${GAUSSHOME}/bin
SCRIPT_NAME=$0

usage()
{
    echo "Usage: $0 [cmd] [grserver_id] [GR_HOME] [GSDB_HOME]"
    echo "cmd:"
    echo "    -start: start grserver"
    echo "    -stop: stop grserver"
    echo "    -check: check grserver"
    echo "    -clean: clean grserver&${GSDB_BIN}"
    echo "    -reg: register grserver"
    echo "    -unreg: unregister grserver"
    echo "    -isreg: check whether grserver is registered"
    echo "grserver_id:"
    echo "    grserver id"
    echo "GAUSSHOME:"
    echo "    grserver data path"
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
   echo "[$time][GR]$1" >> ${startgr_log} 2>&1
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

function check_gr_config()
{
    log "[START]Checking gr_inst.ini before start gr..."
    if [[ ! -e ${GR_HOME}/cfg/gr_inst.ini ]]
    then
        log "[START]${GR_HOME}/cfg/gr_inst.ini must exist"
        exit 1
    fi
}

function Check()
{
    gr_status=$(program_status grserver ${GR_HOME})
    if [[ -z ${gr_status} ]]
    then
        log "[CHECK]grserver is offline."
        exit 1
    fi
    if [[ "${gr_status}" == "D" || "${gr_status}" == "T" || "${gr_status}" == "Z" ]]
    then
        log "[CHECK]grserver is dead."
        exit 3
    fi
    ${GR_BIN_CMD} getstatus
    gr_status=$?
    if [ ${gr_status} != 0 ]
    then
        log "[CHECK]grcmd status return code: $gr_status"
        exit 2
    fi
}

CMD=${1}
INSTANCE_ID=${2}
startgr_log=${GR_HOME}/startgr.log

get_startgr_log()
{
    LOG_HOME=`cat ${GR_HOME}/cfg/gr_inst.ini | sed s/[[:space:]]//g |grep -Eo "^LOG_HOME=.*" | awk -F '=' '{print $2}'`
    if [[ ! -z ${LOG_HOME} ]]
    then
        startgr_log=${LOG_HOME}/startgr.log
    fi

    if [[ -z ${GR_HOME} ]]
    then
        startgr_log=/dev/null
    else
        touch_logfile $startgr_log
    fi
}

kill_gr()
{
    pid=$(program_pid grserver ${GR_HOME})
    if [[ -z ${pid} ]]
    then
        log "[${1}]grserver not exist."
        echo "grserver not exist"
    fi
    kill_program grserver ${GR_HOME}
    log "[${1}]Success to kill grserver."
}

function Start()
{
    pid=`program_pid ${GR_BIN_FULL} ${GR_HOME}`
    if [[ ! -z ${pid} ]]
    then
        log "[START]grserver already started in dir ${GR_HOME}..."
    else
        log "[START]Starting weserver..."
        log "[START]grserver"
        #nohup ${GR_BIN_FULL} -D ${GAUSSHOME} >> ${startgr_log} 2>&1  &
        ${GR_BIN_FULL} -D ${GR_HOME} &
        log "[START]start grserver in ${GR_HOME} is starting."
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
    kill_program grserver ${GR_HOME}
}


function Stop()
{
    kill_program grserver ${GR_HOME}
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