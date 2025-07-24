source ../test_home/test_env

function check_wrstatus()
{
    res=`wrcmd getstatus | awk 'NR==1'`
    if [[ $res =~ 'Server status' ]]; then
        echo "wrserver status is normal."
    else
        echo "wrserver status is abnormal, need to repair."
        exit 1
    fi
}

function test_getcfg()
{
    cfg_val=`cat $WR_HOME/cfg/wr_inst.ini | grep _LOG_LEVEL | sed 's/[^0-9]//g'`
    get_val=`wrcmd getcfg -n _LOG_LEVEL | sed 's/[^0-9]//g'`
    if [ $get_val -eq $cfg_val ]; then
        echo "Get cfg param _LOG_LEVEL successfully."
    else
        echo "Failed to get _LOG_LEVEL by wrcmd getcfg."
        exit 1
    fi
}

function test_setcfg()
{
    wrcmd setcfg -n _LOG_LEVEL -v 7
    cfg_val=`cat $WR_HOME/cfg/wr_inst.ini | grep _LOG_LEVEL | sed 's/[^0-9]//g'`
    if [ $cfg_val -eq 7 ]; then
        echo "Set param _LOG_LEVEL successfully."
    else
        echo "Failed to set _LOG_LEVEL by wrcmd setcfg."
        exit 1
    fi
}

function test_lscli()
{
    res=`wrcmd lscli | grep 'wrcmd' | wc -l `
    if [ $res -eq 1 ]; then
        echo "Get client wrcmd info successfully."
    else
        echo "Failed to get client wrcmd info."
        exit 1
    fi
}

function test_stopwr()
{
    wrcmd stopwr
    sleep 10
    res=`ps ux | grep wrserver | grep -v grep | wc -l`
    if [ $res -eq 0 ]; then
        echo "Successfully stop wrserver."
    else
        echo "Failed to stop wrserver."
        exit 1
    fi
}

function recover_env()
{
    wrserver -D $WR_HOME &
    res=`ps ux | grep wrserver | grep -v grep | wc -l`
    sleep 10
    if [ $res -eq 1 ]; then
        echo "Succssfully start wrserver."
    else
        echo "Failed to start wrserver."
        exit 1
    fi
    check_wrstatus

    res=`wrcmd setcfg -n _LOG_LEVEL -v 255`
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
    test_stopwr
    recover_env
}

main