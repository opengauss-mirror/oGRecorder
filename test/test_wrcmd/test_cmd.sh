source ../test_home/test_env

function check_wrstatus()
{
    res=`grcmd getstatus | awk 'NR==1'`
    if [[ $res =~ 'Server status' ]]; then
        echo "grserver status is normal."
    else
        echo "grserver status is abnormal, need to repair."
        exit 1
    fi
}

function test_getcfg()
{
    cfg_val=`cat $GR_HOME/cfg/gr_inst.ini | grep _LOG_LEVEL | sed 's/[^0-9]//g'`
    get_val=`grcmd getcfg -n _LOG_LEVEL | sed 's/[^0-9]//g'`
    if [ $get_val -eq $cfg_val ]; then
        echo "Get cfg param _LOG_LEVEL successfully."
    else
        echo "Failed to get _LOG_LEVEL by grcmd getcfg."
        exit 1
    fi
}

function test_setcfg()
{
    grcmd setcfg -n _LOG_LEVEL -v 7
    cfg_val=`cat $GR_HOME/cfg/gr_inst.ini | grep _LOG_LEVEL | sed 's/[^0-9]//g'`
    if [ $cfg_val -eq 7 ]; then
        echo "Set param _LOG_LEVEL successfully."
    else
        echo "Failed to set _LOG_LEVEL by grcmd setcfg."
        exit 1
    fi
}

function test_lscli()
{
    res=`grcmd lscli | grep 'grcmd' | wc -l `
    if [ $res -eq 1 ]; then
        echo "Get client grcmd info successfully."
    else
        echo "Failed to get client grcmd info."
        exit 1
    fi
}

function test_stop()
{
    grcmd stop
    sleep 10
    res=`ps ux | grep grserver | grep -v grep | wc -l`
    if [ $res -eq 0 ]; then
        echo "Successfully stop grserver."
    else
        echo "Failed to stop grserver."
        exit 1
    fi
}

function recover_env()
{
    grserver -D $GR_HOME &
    res=`ps ux | grep grserver | grep -v grep | wc -l`
    sleep 10
    if [ $res -eq 1 ]; then
        echo "Succssfully start grserver."
    else
        echo "Failed to start grserver."
        exit 1
    fi
    check_wrstatus

    res=`grcmd setcfg -n _LOG_LEVEL -v 255`
    if [[ $res =~ $"Succeed" ]]; then
        echo "Successfully set _LOG_LEVEL to 255."
    else
        echo "Failed to set _LOG_LEVEL."
        exit 1
    fi
}

main()
{
    check_wrstatus
    test_getcfg
    test_setcfg
    test_lscli
    test_stop
    recover_env
}

main