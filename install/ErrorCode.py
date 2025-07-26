# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : ErrorCode.py is utility to register the error message
#############################################################################
import re
import sys


class ErrorCode():
    """
    Class to define output about the error message
    """

    def __init__(self):
        pass

    @staticmethod
    def getErrorCodeAsInt(ex, default_error_code):
        """
        Resolve the exit code from the exception instance or error message.

        In linux, the range of return values is between 0 and 255.
        So we can only use each type of error code as exit code.Such as:
            ErrorCode.GAUSS_500 : 10
            ErrorCode.GAUSS_501 : 11

        :param ex:                  Exception instance or error message
        :param default_error_code:  If the exception instance does not contain
        the exit code, use this parameter.

        :type ex:                   Exception | str
        :type default_error_code:   int

        :return:    Return the error code.
            9 represents undefined exit code.
            other number between 0 and 255 represent the specific gauss error.
        :type:      int
        """
        error_message = str(ex)
        pattern = r"^[\S\s]*\[GAUSS-(\d+)\][\S\s]+$"
        match = re.match(pattern, error_message)

        if match is not None and len(match.groups()) == 1:
            error_code = int(match.groups()[0])
        else:
            error_code = default_error_code

        if 50000 < error_code < 60000:
            return error_code // 100 - 500 + 10
        else:
            return 9

    ###########################################################################
    # parameter
    ###########################################################################
    GAUSS_500 = {
        'GAUSS_50000': "[GAUSS-50000] : Unrecognized parameter: %s.",
        'GAUSS_50001': "[GAUSS-50001] : Incorrect parameter. Parameter "
                       "'-%s' is required",
        'GAUSS_50002': "[GAUSS-50002] : Incorrect parameter. Parameter "
                       "'-%s' is not required",
        'GAUSS_50003': "[GAUSS-50003] : The parameter '-%s' type should be "
                       "%s.",
        'GAUSS_50004': "[GAUSS-50004] : The parameter '-%s' value is "
                       "incorrect.",
        'GAUSS_50005': "[GAUSS-50005] : The parameter '-%s' and '-%s' "
                       "can not be used together.",
        'GAUSS_50006': "[GAUSS-50006] : Too many command-line arguments "
                       "(first is \"%s\").",
        'GAUSS_50007': "[GAUSS-50007] : Failed to set %s parameter.",
        'GAUSS_50008': "[GAUSS-50008] : Failed to reload parameter.",
        'GAUSS_50009': "[GAUSS-50009] : Parameter format error.",
        'GAUSS_50010': "[GAUSS-50010] : Failed to check %s parameter.",
        'GAUSS_50011': "[GAUSS-50011] : The parameter[%s] value[%s] "
                       "is invalid.",
        'GAUSS_50012': "[GAUSS-50012] : The parameter '%s' value can't "
                       "be empty.",
        'GAUSS_50013': "[GAUSS-50013] : The parameter '%s' have not "
                       "been initialized.",
        'GAUSS_50014': "[GAUSS-50014] : Parameters of '%s' can not be empty.",
        'GAUSS_50015': "[GAUSS-50015] : The command line parser error: %s.",
        'GAUSS_50016': "[GAUSS-50016] : The re-entrant parameter '-%s' "
                       "is not same with the previous command.",
        'GAUSS_50017': "[GAUSS-50017] : Incorrect value '%s' specified "
                       "by the parameter '-%s'.",
        'GAUSS_50018': "[GAUSS-50018] : The parameter value of %s is Null.",
        'GAUSS_50019': "[GAUSS-50019] : The value of %s is error.",
        'GAUSS_50020': "[GAUSS-50020] : The value of %s must be a digit.",
        'GAUSS_50021': "[GAUSS-50021] : Failed to query %s parameter.",
        'GAUSS_50022': "[GAUSS-50022] : The parameter '%s' should be %s.",
        'GAUSS_50023': "[GAUSS-50023] : The parameter '%s' over max length %s.",
        'GAUSS_50024': "[GAUSS-50024] : The parameter '%s' is invalid.",
        'GAUSS_50025': "[GAUSS-50025] : There is illegal character '%s' in parameter %s.",
        'GAUSS_50026': "[GAUSS-50026] : Failed to check %s parameters in the XML file.",
        'GAUSS_50027': "[GAUSS-50027] : Parameter '%s' format error.",
        'GAUSS_50028': "[GAUSS-50028] : Non root users do not support setting %s parameters."
    }

    ###########################################################################
    # permission
    ###########################################################################

    GAUSS_501 = {
        'GAUSS_50100': "[GAUSS-50100] : The %s is not readable for %s.",
        'GAUSS_50101': "[GAUSS-50101] : The %s is not executable for %s.",
        'GAUSS_50102': "[GAUSS-50102] : The %s is not writable for %s.",
        'GAUSS_50103': "[GAUSS-50103] : The %s has unexpected rights.",
        'GAUSS_50104': "[GAUSS-50104] : Only a user with the root permission "
                       "can run this script.",
        'GAUSS_50105': "[GAUSS-50105] : Cannot run this script as a user "
                       "with the root permission.",
        'GAUSS_50106': "[GAUSS-50106] : Failed to change the owner of %s.",
        'GAUSS_50107': "[GAUSS-50107] : Failed to change the "
                       "permission of %s.",
        'GAUSS_50108': "[GAUSS-50108] : Failed to change the owner and "
                       "permission of %s.",
        'GAUSS_50109': "[GAUSS-50109] : Only a user with the root permission "
                       "can check SSD information.",
        'GAUSS_50110': "[GAUSS-50110] : Cannot execute this script on %s.",
        'GAUSS_50111': "[GAUSS-50111] : The %s directory has no permission.",
        'GAUSS_50112': "[GAUSS-50112] : Failed to get the permission of %s.",
    }

    ###########################################################################
    # file or directory
    ###########################################################################
    GAUSS_502 = {
        'GAUSS_50200': "[GAUSS-50200] : The %s already exists.",
        'GAUSS_50201': "[GAUSS-50201] : The %s does not exist.",
        'GAUSS_50202': "[GAUSS-50202] : The %s must be empty.",
        'GAUSS_50203': "[GAUSS-50203] : The %s cannot be empty.",
        'GAUSS_50204': "[GAUSS-50204] : Failed to read %s.",
        'GAUSS_50205': "[GAUSS-50205] : Failed to write %s.",
        'GAUSS_50206': "[GAUSS-50206] : Failed to create %s.",
        'GAUSS_50207': "[GAUSS-50207] : Failed to delete %s.",
        'GAUSS_50208': "[GAUSS-50208] : Failed to create the %s directory.",
        'GAUSS_50209': "[GAUSS-50209] : Failed to delete the %s directory.",
        'GAUSS_50210': "[GAUSS-50210] : The %s must be a file.",
        'GAUSS_50211': "[GAUSS-50211] : The %s must be a directory.",
        'GAUSS_50212': "[GAUSS-50212] : The suffix of the file [%s] "
                       "should be '%s'.",
        'GAUSS_50213': "[GAUSS-50213] : The %s path must be an absolute path.",
        'GAUSS_50214': "[GAUSS-50214] : Failed to copy %s.",
        'GAUSS_50215': "[GAUSS-50215] : Failed to back up %s.",
        'GAUSS_50216': "[GAUSS-50216] : Failed to remote copy %s.",
        'GAUSS_50217': "[GAUSS-50217] : Failed to decompress %s.",
        'GAUSS_50218': "[GAUSS-50218] : Failed to rename %s.",
        'GAUSS_50219': "[GAUSS-50219] : Failed to obtain %s.",
        'GAUSS_50220': "[GAUSS-50220] : Failed to restore %s.",
        'GAUSS_50221': "[GAUSS-50221] : Failed to obtain file type.",
        'GAUSS_50222': "[GAUSS-50222] : The content of file %s is not "
                       "correct.",
        'GAUSS_50223': "[GAUSS-50223] : Failed to update %s files.",
        'GAUSS_50224': "[GAUSS-50224] : The file name is incorrect.",
        'GAUSS_50225': "[GAUSS-50225] : Failed to back up remotely.",
        'GAUSS_50226': "[GAUSS-50226] : Failed to restore remotely.",
        'GAUSS_50227': "[GAUSS-50227] : Failed to compress %s.",
        'GAUSS_50228': "[GAUSS-50228] : The %s does not exist or is empty.",
        'GAUSS_50229': "[GAUSS-50229] : Cannot specify the file [%s] to "
                       "the cluster path %s.",
        'GAUSS_50230': "[GAUSS-50230] : Failed to read/write %s.",
        'GAUSS_50231': "[GAUSS-50231] : Failed to generate %s file.",
        'GAUSS_50232': "[GAUSS-50232] : The instance directory [%s] "
                       "cannot set in app directory [%s].Please check "
                       "the xml.",
        'GAUSS_50233': "[GAUSS-50233] : The directory name %s and %s "
                       "cannot be same.",
        'GAUSS_50234': "[GAUSS-50234] : Cannot execute the script in "
                       "the relevant path of the database.",
        'GAUSS_50235': "[GAUSS-50235] : The log file name [%s] can not contain"
                       " more than one '.'.",
        'GAUSS_50236': "[GAUSS-50236] : The %s does not exist or "
                       "the permission on the upper-layer directory is insufficient.",
        'GAUSS_50237': "[GAUSS-50237] : Send result file failed nodes: %s;"
                       " outputMap: %s",
        'GAUSS_50238': "[GAUSS-50238] : Check integrality of bin ",
                       "file %s failed."
        'GAUSS_50239': "[GAUSS-50239] : %s should be set in scene config "
                                      "file.",
        'GAUSS_50240': "[GAUSS-50240] : %s, it not allowed that directory dss_home_path is a subset"
                                      "of Directory datanode_path."
    }

    ###########################################################################
    # user and group
    ###########################################################################
    GAUSS_503 = {
        'GAUSS_50300': "[GAUSS-50300] : User %s does not exist.",
        'GAUSS_50301': "[GAUSS-50301] : The cluster user/group cannot "
                       "be a root user/group.",
        'GAUSS_50302': "[GAUSS-50302] : The cluster user cannot be a user "
                       "with the root permission.",
        'GAUSS_50303': "[GAUSS-50303] : Cannot install the program as a "
                       "user with the root permission.",
        'GAUSS_50304': "[GAUSS-50304] : The new user [%s] is not the same "
                       "as the old user [%s].",
        'GAUSS_50305': "[GAUSS-50305] : The user is not matched with the "
                       "user group.",
        'GAUSS_50306': "[GAUSS-50306] : The password of %s is incorrect.",
        'GAUSS_50307': "[GAUSS-50307] : User password has expired.",
        'GAUSS_50308': "[GAUSS-50308] : Failed to obtain user information.",
        'GAUSS_50309': "[GAUSS-50309] : Failed to obtain password "
                       "change times of data base super user",
        'GAUSS_50310': "[GAUSS-50310] : Failed to obtain password "
                       "expiring days.",
        'GAUSS_50311': "[GAUSS-50311] : Failed to change password for %s.",
        'GAUSS_50312': "[GAUSS-50312] : There are other users in the group %s "
                       "on %s, skip to delete group.",
        'GAUSS_50313': "[GAUSS-50313] : Failed to delete %s group.",
        'GAUSS_50314': "[GAUSS-50314] : Failed to delete %s user.",
        'GAUSS_50315': "[GAUSS-50315] : The user %s is not matched with the "
                       "owner of %s.",
        'GAUSS_50316': "[GAUSS-50316] : Group [%s] does not exist.",
        'GAUSS_50317': "[GAUSS-50317] : Failed to check user and password.",
        'GAUSS_50318': "[GAUSS-50318] : Failed to add %s user.",
        'GAUSS_50319': "[GAUSS-50319] : Failed to add %s group.",
        'GAUSS_50320': "[GAUSS-50320] : Failed to set '%s' to '%s' in "
                       "/etc/ssh/sshd_config.",
        'GAUSS_50321': "[GAUSS-50321] : Failed to get configuration of '%s' "
                       "from /etc/ssh/sshd_config.",
        'GAUSS_50322': "[GAUSS-50322] : Failed to encrypt the password for %s",
        'GAUSS_50323': "[GAUSS-50323] : The user %s is not the cluster "
                       "installation user ",
        'GAUSS_50324': "[GAUSS-50324] : Non root user, -U -G parameter must be the current user and group."
    }

    ###########################################################################
    # disk
    ###########################################################################
    GAUSS_504 = {
        'GAUSS_50400': "[GAUSS-50400] : The remaining space of device [%s] "
                       "cannot be less than %s.",
        'GAUSS_50401': "[GAUSS-50401] : The usage of the device [%s] space "
                       "cannot be greater than %s.",
        'GAUSS_50402': "[GAUSS-50402] : The usage of INODE cannot be greater "
                       "than %s.",
        'GAUSS_50403': "[GAUSS-50403] : The IO scheduling policy is "
                       "incorrect.",
        'GAUSS_50404': "[GAUSS-50404] : The XFS mount type must be %s.",
        'GAUSS_50405': "[GAUSS-50405] : The pre-read block size must "
                       "be 16384.",
        'GAUSS_50406': "[GAUSS-50406] : Failed to obtain disk read and "
                       "write rates.",
        'GAUSS_50407': "[GAUSS-50407] : Failed to clean shared semaphore.",
        'GAUSS_50408': "[GAUSS-50408] : Failed to obtain disk read-ahead "
                       "memory block.",
        'GAUSS_50409': "[GAUSS-50409] : The remaining space of dns cannot "
                       "support shrink.",
        'GAUSS_50410': "[GAUSS-50410] : Failed to check if remaining space "
                       "of dns support shrink.",
        'GAUSS_50411': "[GAUSS-50411] : The remaining space cannot be less "
                       "than %s.",
        'GAUSS_50412': "[GAUSS-50412] : Failed to get disk space of database "
                       "node %s.",
        'GAUSS_50413': "[GAUSS-50413] : Failed to analysis"
                       " the disk information.",
        'GAUSS_50414': "[GAUSS-50414] : Failed to get the volume information. Error: %s",
        'GAUSS_50415': "[GAUSS-50415] : Failed to obtain the public volume '%s'.",
        'GAUSS_50416': "[GAUSS-50416] : Failed to obtain the private volume %s.",
        'GAUSS_50417': "[GAUSS-50417] : The configuration cannot contain " \
        "the same volume information.",
        'GAUSS_50418': "[GAUSS-50418] : Failed to obtain the disk '%s'.",
        'GAUSS_50419': "[GAUSS-50419] : Failed to obtain the public volume '%s' in '%s'.",
        'GAUSS_50420': "[GAUSS-50420] : Failed to obtain the volume",
        'GAUSS_50421': "[GAUSS-50421] : Failed to obtain the disk '%s'",
        'GAUSS_50422': "[GAUSS-50422] : Failed to obtain the uuid of the '%s'",
        'GAUSS_50423': "[GAUSS-50423] : Failed to activating udev configurations, error: '%s'",
    }

    ###########################################################################
    # network
    ###########################################################################
    GAUSS_506 = {
        'GAUSS_50600': "[GAUSS-50600] : The IP address cannot be pinged, "
                       "which is caused by network faults.",
        'GAUSS_50601': "[GAUSS-50601] : The port [%s] is occupied or the ip "
                       "address is incorrectly configured.",
        'GAUSS_50602': "[GAUSS-50602] : Failed to bind network adapters.",
        'GAUSS_50603': "[GAUSS-50603] : The IP address is invalid.",
        'GAUSS_50604': "[GAUSS-50604] : Failed to obtain network interface "
                       "card of backIp(%s).",
        'GAUSS_50605': "[GAUSS-50605] : Failed to obtain back IP subnet mask.",
        'GAUSS_50606': "[GAUSS-50606] : Back IP(s) do not have the same "
                       "subnet mask.",
        'GAUSS_50607': "[GAUSS-50607] : Failed to obtain configuring virtual "
                       "IP line number position of network startup file.",
        'GAUSS_50608': "[GAUSS-50608] : Failed to writing virtual IP setting "
                       "cmds into init file.",
        'GAUSS_50609': "[GAUSS-50609] : Failed to check port: %s.",
        'GAUSS_50610': "[GAUSS-50610] : Failed to get the range of "
                       "random port.",
        'GAUSS_50611': "[GAUSS-50611] : Failed to obtain network card "
                       "bonding information.",
        'GAUSS_50612': "[GAUSS-50612] : Failed to obtain network card %s "
                       "value.",
        'GAUSS_50613': "[GAUSS-50613] : Failed to set network card %s value.",
        'GAUSS_50614': "[GAUSS-50614] : Failed to check network information.",
        'GAUSS_50615': "[GAUSS-50615] : IP %s and IP %s are not in the "
                       "same network segment.",
        'GAUSS_50616': "[GAUSS-50616] : Failed to get network interface.",
        'GAUSS_50617': "[GAUSS-50617] : The node of XML configure file "
                       "has the same virtual IP.",
        'GAUSS_50618': "[GAUSS-50618] : %s. The startup file for SUSE OS"
                       " is /etc/init.d/boot.local. The startup file for "
                       "Redhat OS is /etc/rc.d/rc.local.",
        'GAUSS_50619': "[GAUSS-50619] : Failed to obtain network"
                       " card information.",
        'GAUSS_50620': "[GAUSS-50620] : Failed to check network"
                       " RX drop percentage.",
        'GAUSS_50621': "[GAUSS-50621] : Failed to check network care speed.\n",
        'GAUSS_50622': "[GAUSS-50622] : Failed to obtain network card "
                       "interrupt count numbers. Commands for getting "
                       "interrupt count numbers: %s.\n",
        'GAUSS_50623': "[GAUSS-50623] : Failed to check all datanode connections. Successfully connected to %s datanodes.",
        'GAUSS_50624': "[GAUSS-50624] : The types of these ip addresses are inconsistent.",
        'GAUSS_50625': "[GAUSS-50625] : The ip address of the cluster block is inconsistent "
                       "with that of the device."

    }

    ###########################################################################
    # crontab
    ###########################################################################
    GAUSS_508 = {
        'GAUSS_50800': "[GAUSS-50800] : Regular tasks are not started.",
        'GAUSS_50801': "[GAUSS-50801] : Failed to set up tasks.",
        'GAUSS_50802': "[GAUSS-50802] : Failed to %s service.",
        'GAUSS_50803': "[GAUSS-50803] : Failed to check user cron."
    }

    ###########################################################################
    # THP
    ###########################################################################
    GAUSS_510 = {
        'GAUSS_51000': "[GAUSS-51000] : THP services must be shut down.",
        'GAUSS_51001': "[GAUSS-51001] : Failed to obtain THP service.",
        'GAUSS_51002': "[GAUSS-51002] : Failed to close THP service.",
        'GAUSS_51003': "[GAUSS-51003] : Failed to set session process."
    }

    ###########################################################################
    # SSH trust
    ###########################################################################
    GAUSS_511 = {
        'GAUSS_51100': "[GAUSS-51100] : Failed to verify SSH trust on "
                       "these nodes: %s.",
        'GAUSS_51101': "[GAUSS-51101] : SSH exception: \n%s",
        'GAUSS_51102': "[GAUSS-51102] : Failed to exchange SSH keys "
                       "for user [%s] performing the %s operation.",
        'GAUSS_51103': "[GAUSS-51103] : Failed to execute the PSSH "
                       "command [%s].",
        'GAUSS_51104': "[GAUSS-51104] : Failed to obtain SSH status.",
        'GAUSS_51105': "[GAUSS-51105] : Failed to parse SSH output: %s.",
        'GAUSS_51106': "[GAUSS-51106] : The SSH tool does not exist.",
        'GAUSS_51107': "[GAUSS-51107] : Ssh Paramiko failed.",
        'GAUSS_51108': "[GAUSS-51108] : Ssh-keygen failed.",
        'GAUSS_51109': "[GAUSS-51109] : Failed to check authentication.",
        'GAUSS_51110': "[GAUSS-51110] : Failed to obtain RSA host key "
                       "for local host.",
        'GAUSS_51111': "[GAUSS-51111] : Failed to append local ID to "
                       "authorized_keys on remote node.",
        'GAUSS_51112': "[GAUSS-51112] : Failed to exchange SSH keys "
                       "for user[%s] using hostname.",
        'GAUSS_51113': "[GAUSS-51113] : Failed to generate passphrase keyword.",
        "GAUSS_51114": "[GAUSS-51114] : Failed to obtain %s by %s.",
        "GAUSS_51115": "[GAUSS-51115] : Failed to obtain hostname by %s.",
        "GAUSS_51116": "[GAUSS-51116] : The IP address %s or %s is incorrect."

    }

    ###########################################################################
    # cluster/XML configruation
    ###########################################################################
    GAUSS_512 = {
        'GAUSS_51200': "[GAUSS-51200] : The parameter [%s] in the XML "
                       "file does not exist.",
        'GAUSS_51201': "[GAUSS-51201] : Node names must be configured.",
        'GAUSS_51202': "[GAUSS-51202] : Failed to add the %s instance.",
        'GAUSS_51203': "[GAUSS-51203] : Failed to obtain the %s "
                       "information from static configuration files.",
        'GAUSS_51204': "[GAUSS-51204] : Invalid %s instance type: %d.",
        'GAUSS_51205': "[GAUSS-51205] : Failed to refresh the %s instance ID.",
        'GAUSS_51206': "[GAUSS-51206] : The MPPRC file path must "
                       "be an absolute path: %s.",
        'GAUSS_51207': "[GAUSS-51207] : Failed to obtain backIp "
                       "from node [%s].",
        'GAUSS_51208': "[GAUSS-51208] : Invalid %s number [%d].",
        'GAUSS_51209': "[GAUSS-51209] : Failed to obtain %s "
                       "configuration on the host [%s].",
        'GAUSS_51210': "[GAUSS-51210] : The obtained number does "
                       "not match the instance number.",
        'GAUSS_51211': "[GAUSS-51211] : Failed to save a static "
                       "configuration file.",
        'GAUSS_51212': "[GAUSS-51212] : There is no information about %s.",
        'GAUSS_51213': "[GAUSS-51213] : The port number of XML [%s] "
                       "conflicted.",
        'GAUSS_51214': "[GAUSS-51214] : The number of capacity expansion "
                       "database nodes cannot be less than three",
        'GAUSS_51215': "[GAUSS-51215] : The capacity expansion node [%s] "
                       "cannot contain GTM/CM/ETCD.",
        'GAUSS_51216': "[GAUSS-51216] : The capacity expansion node [%s] "
                       "must contain CN or DN.",
        'GAUSS_51217': "[GAUSS-51217] : The cluster's static configuration "
                       "does not match the new configuration file.",
        'GAUSS_51218': "[GAUSS-51218] : Failed to obtain initialized "
                       "configuration parameter: %s.",
        'GAUSS_51219': "[GAUSS-51219] : There is no CN in cluster.",
        'GAUSS_51220': "[GAUSS-51220] : The IP address %s is incorrect.",
        'GAUSS_51221': "[GAUSS-51221] : Failed to configure hosts "
                       "mapping information.",
        'GAUSS_51222': "[GAUSS-51222] : Failed to check hostname mapping.",
        'GAUSS_51223': "[GAUSS-51223] : Failed to obtain network "
                       "inet addr on the node(%s).",
        'GAUSS_51224': "[GAUSS-51224] : The ip(%s) has been used "
                       "on other nodes.",
        'GAUSS_51225': "[GAUSS-51225] : Failed to set virtual IP.",
        'GAUSS_51226': "[GAUSS-51226] : Virtual IP(s) and Back IP(s) "
                       "do not have the same network segment.",
        'GAUSS_51227': "[GAUSS-51227] : The number of %s on all nodes "
                       "are different.",
        'GAUSS_51228': "[GAUSS-51228] : The number %s does not "
                       "match %s number.",
        'GAUSS_51229': "[GAUSS-51229] : The database node listenIp(%s) is not "
                       "in the virtualIp or backIp on the node(%s).",
        'GAUSS_51230': "[GAUSS-51230] : The number of %s must %s.",
        'GAUSS_51231': "[GAUSS-51231] : Old nodes is less than 2.",
        'GAUSS_51232': "[GAUSS-51232] : XML configuration and static "
                       "configuration are the same.",
        'GAUSS_51233': "[GAUSS-51233] : The Port(%s) is invalid "
                       "on the node(%s).",
        'GAUSS_51234': "[GAUSS-51234] : The configuration file [%s] "
                       "contains parsing errors.",
        'GAUSS_51235': "[GAUSS-51235] : Invalid directory [%s].",
        'GAUSS_51236': "[GAUSS-51236] : Failed to parsing xml.The XML file format is incorrect.",
        'GAUSS_51239': "[GAUSS-51239] : Failed to parse json. gs_collect "
                       "configuration file (%s) is invalid , "
                       "check key in json file",
        'GAUSS_51240': "[GAUSS-51240] : gs_collect configuration file "
                       "is invalid, TypeName or content must in config file.",
        'GAUSS_51241': "[GAUSS-51241] : The parameter %s(%s) formate "
                       "is wrong, or value is less than 0.",
        'GAUSS_51242': "[GAUSS-51242] : gs_collect configuration file "
                       "is invalid: %s, the key: (%s) is invalid.",
        'GAUSS_51243': "[GAUSS-51243] : content(%s) does not match the "
                       "typename(%s) in gs_collect configuration file(%s).",
        'GAUSS_51244': "[GAUSS-51244] : (%s) doesn't yet support.",
        'GAUSS_51245': "[GAUSS-51245] : There are duplicate key(%s).",
        'GAUSS_51246': "[GAUSS-51246] : %s info only support "
                       "one time collect.",
        'GAUSS_51247': "[GAUSS-51247] : These virtual IP(%s) are not "
                       "accessible after configuring.",
        'GAUSS_51248': "[GAUSS-51248] : The hostname(%s) may be not same with "
                       "hostname(/etc/hostname)",
        'GAUSS_51249': "[GAUSS-51249] : There is no database node instance "
                       "in the current node.",
        'GAUSS_51250': "[GAUSS-51250] : Error: the '%s' is illegal.\nthe path "
                       "name or file name should be letters, number or -_:.",
        'GAUSS_51251': "[GAUSS-51251] : The %s cannot be a root user group or a link.",
        'GAUSS_51252': "[GAUSS-51252] : Failed to start the DSS server. Please check the dss logs.",
        'GAUSS_51253': "[GAUSS-51253] : Failed to clear the shared memory of the user. Error %s.",
        'GAUSS_51254': "[GAUSS-51254] : Failed to kill dssserver. Error %s.",
        'GAUSS_51255': "[GAUSS-51255] : Failed to reencrypt the password with dsscmd",
        'GAUSS_51256': "[GAUSS-51256] : Failed to get the encrypted text with dsscmd",
        'GAUSS_51257': "[GAUSS-51257] : There are some errors about dsscmd. ",
        'GAUSS_51258': "[GAUSS-51258] : The parameter [%s] in the XML "
                       "file is an incorrect parameter.",

    }

    ###########################################################################
    # Shell exception
    ###########################################################################
    GAUSS_514 = {
        'GAUSS_51400': "[GAUSS-51400] : Failed to execute the command: %s.",
        'GAUSS_51401': "[GAUSS-51401] : Failed to do %s.sh.",
        'GAUSS_51402': "[GAUSS-51402]: Failed to generate certs.",
        'GAUSS_51403': "[GAUSS-51403]: commond execute failure,"
                       " check %s failed!",
        'GAUSS_51404': "[GAUSS-51404] : Not supported command %s.",
        'GAUSS_51405': "[GAUSS-51405] : You need to install software:%s\n",
        'GAUSS_51406': "[GAUSS-51406] : The uuid of disk '%s' is the same " \
            "configuration under directory '%s'."
    }

    ###########################################################################
    # cluster/instance status
    ###########################################################################
    GAUSS_516 = {
        'GAUSS_51600': "[GAUSS-51600] : Failed to obtain the cluster status.",
        'GAUSS_51601': "[GAUSS-51601] : Failed to check %s status.",
        'GAUSS_51602': "[GAUSS-51602] : The cluster status is Abnormal.",
        'GAUSS_51603': "[GAUSS-51603] : Failed to obtain peer %s instance.",
        'GAUSS_51604': "[GAUSS-51604] : There is no HA status for %s.",
        'GAUSS_51605': "[GAUSS-51605] : Failed to check whether "
                       "the %s process exists.",
        'GAUSS_51606': "[GAUSS-51606] : Failed to kill the %s process.",
        'GAUSS_51607': "[GAUSS-51607] : Failed to start %s.",
        'GAUSS_51608': "[GAUSS-51608] : Failed to lock cluster",
        'GAUSS_51609': "[GAUSS-51609] : Failed to unlock cluster",
        'GAUSS_51610': "[GAUSS-51610] : Failed to stop %s.",
        'GAUSS_51611': "[GAUSS-51611] : Failed to create %s instance.",
        'GAUSS_51612': "[GAUSS-51612] : The node id [%u] are not found "
                       "in the cluster.",
        'GAUSS_51613': "[GAUSS-51613] : There is no instance in %s to "
                       "be built.",
        'GAUSS_51614': "[GAUSS-51614] : Received signal[%d].",
        'GAUSS_51615': "[GAUSS-51615] : Failed to initialize instance.",
        'GAUSS_51616': "[GAUSS-51616] : Failed to dump %s schema.",
        'GAUSS_51617': "[GAUSS-51617] : Failed to rebuild %s.",
        'GAUSS_51618': "[GAUSS-51618] : Failed to get all hostname.",
        'GAUSS_51619': "[GAUSS-51619] : The host name [%s] is not "
                       "in the cluster.",
        'GAUSS_51620': "[GAUSS-51620] : Failed to obtain %s "
                       "instance information.",
        'GAUSS_51621': "[GAUSS-51621] : HA IP is empty.",
        'GAUSS_51622': "[GAUSS-51622] : There is no %s on %s node.",
        'GAUSS_51623': "[GAUSS-51623] : Failed to obtain version.",
        'GAUSS_51624': "[GAUSS-51624] : Failed to get DN connections.",
        'GAUSS_51625': "[GAUSS-51625] : Cluster is running.",
        'GAUSS_51626': "[GAUSS-51626] : Failed to rollback.",
        'GAUSS_51627': "[GAUSS-51627] : Configuration failed.",
        'GAUSS_51628': "[GAUSS-51628] : The version number of new cluster "
                       "is [%s]. It should be float.",
        'GAUSS_51629': "[GAUSS-51629] : The version number of new cluster "
                       "is [%s]. It should be greater than or equal to "
                       "the old version.",
        'GAUSS_51630': "[GAUSS-51630] : No node named %s.",
        'GAUSS_51631': "[GAUSS-51631] : Failed to delete the %s instance.",
        'GAUSS_51632': "[GAUSS-51632] : Failed to do %s.",
        'GAUSS_51633': "[GAUSS-51633] : The step of upgrade "
                       "number %s is incorrect.",
        'GAUSS_51634': "[GAUSS-51634] : Waiting node synchronizing timeout "
                       "lead to failure.",
        'GAUSS_51635': "[GAUSS-51635] : Failed to check SHA256.",
        'GAUSS_51636': "[GAUSS-51636] : Failed to obtain %s node information.",
        'GAUSS_51637': "[GAUSS-51637] : The %s does not match with %s.",
        'GAUSS_51638': "[GAUSS-51638] : Failed to append instance on "
                       "host [%s].",
        'GAUSS_51639': "[GAUSS-51639] : Failed to obtain %s status of "
                       "local node.",
        'GAUSS_51640': "[GAUSS-51640] : Can't connect to cm_server, cluster "
                       "is not running possibly.",
        'GAUSS_51641': "[GAUSS-51641] : Cluster redistributing status is not "
                       "accord with expectation.",
        'GAUSS_51642': "[GAUSS-51642] : Failed to promote peer instances.",
        'GAUSS_51643': "[GAUSS-51643] : Cluster is in read-only mode.",
        'GAUSS_51644': "[GAUSS-51644] : Failed to set resource control "
                       "for the cluster.",
        'GAUSS_51645': "[GAUSS-51645] : Failed to restart %s.",
        'GAUSS_51646': "[GAUSS-51646] : The other OM operation is currently "
                       "being performed in the cluster node:"
                       " '%s'.",
        'GAUSS_51647': "[GAUSS-51647] : The operation step of OM components "
                       "in current cluster nodes do not match"
                       " with each other: %s.",
        'GAUSS_51648': "[GAUSS-51648] : Waiting for redistribution process "
                       "to end timeout.",
        'GAUSS_51649': "[GAUSS-51649] : Capture exceptions '%s' : %s.",
        'GAUSS_51650': "[GAUSS-51650] : Unclassified exceptions: %s.",
        'GAUSS_51651': "[GAUSS-51651] : The node '%s' status is Abnormal.\n"
                       "It is required that all the nodes should be normal "
                       "except the target ones.\nPlease add this node in the"
                       " list after -h if it is also a target one.",
        'GAUSS_51652': "[GAUSS-51652] : Failed to get cluster node "
                       "info.exception is: %s.",
        'GAUSS_51653': "[GAUSS-51653] : No database objects "
                       "were found in the cluster!",
        'GAUSS_51654': "[GAUSS-51654] : Cannot query instance process"
                       " version from function.",
        'GAUSS_51655': "[GAUSS-51655] : There is %s on the cluster when operating on a cluster"
                       "the %s parameter is not needed.",
        'GAUSS_51656': "[GAUSS-51656] : Waiting for udev trigger to end timeout",
        'GAUSS_51657': "[GAUSS-51657] : Waiting for start %s to end timeout",
        'GAUSS_51658': "[GAUSS-51658] : The azName is different, and the value of azPriority must be different. "
    }

    ###########################################################################
    # environmental variable
    ###########################################################################
    GAUSS_518 = {
        'GAUSS_51800': "[GAUSS-51800] : The environmental variable %s is "
                       "empty. or variable has exceeded maximum length",
        'GAUSS_51801': "[GAUSS-51801] : The environment variable %s exists.",
        'GAUSS_51802': "[GAUSS-51802] : Failed to obtain the environment "
                       "variable %s.",
        'GAUSS_51803': "[GAUSS-51803] : Failed to delete the environment "
                       "variable %s.",
        'GAUSS_51804': "[GAUSS-51804] : Failed to set the environment "
                       "variable %s.",
        'GAUSS_51805': "[GAUSS-51805] : The environmental variable [%s]'s "
                       "value is invalid.",
        'GAUSS_51806': "[GAUSS-51806] : The cluster has been installed.",
        'GAUSS_51807': "[GAUSS-51807] : $GAUSSHOME of user is not equal to "
                       "installation path.",
        'GAUSS_51808': "[GAUSS-51808] : The env file contains errmsg: %s."
    }

    ###########################################################################
    # OS character set
    ###########################################################################
    GAUSS_522 = {
        'GAUSS_52200': "[GAUSS-52200] : Unable to import module: %s.",
        'GAUSS_52201': "[GAUSS-52201] : The current python version %s "
                       "is not supported."
    }

    ###########################################################################
    # preinsatll install
    ###########################################################################
    GAUSS_524 = {
        'GAUSS_52400': "[GAUSS-52400] : Installation environment does not "
                       "meet the desired result.",
        'GAUSS_52401': "[GAUSS-52401] : On systemwide basis, the maximum "
                       "number of %s is not correct. the current %s value is:",
        'GAUSS_52402': "[GAUSS-52402] : IP [%s] is not matched "
                       "with hostname [%s]. \n",
        'GAUSS_52403': "[GAUSS-52403] : Command \"%s\" does not exist or the "
                       "user has no execute permission on %s."
    }

    ###########################################################################
    # uninsatll postuninstall
    ###########################################################################
    GAUSS_525 = {
        'GAUSS_52500': "[GAUSS-52500] : Failed to delete regular tasks.",
        'GAUSS_52501': "[GAUSS-52501] : Run %s script before "
                       "executing this script.",
        'GAUSS_52502': "[GAUSS-52502] : Another OM process is being executed. "
                       "To avoid conflicts, this process ends in advance."
    }

    ###########################################################################
    # manageCN and changeIP
    ###########################################################################
    GAUSS_528 = {
        'GAUSS_52800': "[GAUSS-52800] : Cluster is %s(%s) now.",
        'GAUSS_52801': "[GAUSS-52801] : Only allow to %s one CN. The %s "
                       "is not matched.",
        'GAUSS_52802': "[GAUSS-52802] : Only allow to add one CN at the end.",
        'GAUSS_52803': "[GAUSS-52803] : There is at least one Normal "
                       "CN after delete CN.",
        'GAUSS_52804': "[GAUSS-52804] : Failed to add the Abnormal CN.",
        'GAUSS_52805': "[GAUSS-52805] : Failed to find another instance as "
                       "model for instance(%s).",
        'GAUSS_52806': "[GAUSS-52806] : Invalid rollback step: %s.",
        'GAUSS_52807': "[GAUSS-52807] : There is no IP changed.",
        'GAUSS_52808': "[GAUSS-52808] : Detected CN %s, but the action is %s.",
        'GAUSS_52809': "[GAUSS-52809] : Only allow to add or delete one CN.",
        'GAUSS_52810': "[GAUSS-52810] : There is Abnormal coodinator(s) "
                       "in cluster, please delete it firstly."
    }

    ###########################################################################
    # Single Primary MultiStandby cluster
    ###########################################################################
    GAUSS_532 = {
        'GAUSS_53200': "[GAUSS-53200] : The number of standbys for each "
                       "database node instance must be the same. "
                       "Please set it.",
        'GAUSS_53201': "[GAUSS-53201] : The number of database node standbys "
                       "and the AZ settings are incorrect. Please set it.",
        'GAUSS_53202': "[GAUSS-53202] : The AZ information is incorrect. "
                       "Please set it.",
        'GAUSS_53203': "[GAUSS-53203] : The number of ETCD in %s. "
                       "Please set it.",
        'GAUSS_53204': "[GAUSS-53204] : [%s] is not supported in single "
                       "primary multistandby cluster.",
        'GAUSS_53205': "[GAUSS-53205] : The priority of %s must be higher "
                       "than %s. Please set it.",
        'GAUSS_53206': "[GAUSS-53206] : The value of %s must be greater "
                       "than 0 and less than 11. Please set it."
    }

class OmError(BaseException):
    """
    Used to record OM exception information and support ErrorCode
    keywords as message information.
    """

    def __init__(self, _message, *args, **kwargs):
        """
        Initialize the OmError instance.

        :param _message:    The input error message, it can be the error
                            message string, or the ErrorCode keywords,
                            or the Exception instance.
        :param args:        The additional unnamed parameters that use
                            to format the error message.
        :param kwargs:      The additional named parameters that use to format
                            the error message or extend to other
                            functions.

        :type _message:     str | BaseException
        :type args:         str | int
        :type kwargs:       str | int
        """
        # If we catch an unhandled exception.
        if isinstance(_message, Exception):
            # Store the error code.
            self._errorCode = ""
            # Store the error message.
            self._message = self.__getErrorMessage(str(_message), args, kwargs)
            # If can not parse the error code.
            if not self._errorCode:
                # Store the error code.
                self._errorCode = "GAUSS_51649"
                # Store the error message.
                self._message = ErrorCode.GAUSS_516[self._errorCode] % (
                    type(_message).__name__, repr(_message))
        else:
            # Store the error code.
            self._errorCode = ""
            # Store the error message.
            self._message = self.__getErrorMessage(_message, args, kwargs)

        # Store the stack information.
        self._stackInfo = sys.exc_info()[2]

    @property
    def message(self):
        """
        Getter, get the error message.

        :return:    Return the error message.
        :rtype:     str
        """
        return self._message

    @property
    def errorCode(self):
        """
        Getter, get the error code.

        :return:    Return the error code.
        :rtype:     str
        """
        return self._errorCode

    def __getErrorMessage(self, _errorCode, args, kwargs):
        """
        Get error information through error code.

        :param _errorCode:  Error code.
        :param args:        Additional parameters.
        :param kwargs:      Additional parameters.

        :type _errorCode:   str
        :type args:         tuple
        :type kwargs:       dict | None

        :return:    Return the error message.
        :rtype:     str
        """
        # Get base error information through error code.
        pattern = r"^[\S\s]*\[(GAUSS-\d+)\][\S\s]+$"
        match = re.match(pattern, str(_errorCode))
        if match and len(match.groups()) == 1:
            self._errorCode = match.groups()[0]
            message = _errorCode
        else:
            self._errorCode = "GAUSS_51650"
            message = ErrorCode.GAUSS_516[self._errorCode] % _errorCode

        # Format parameter which type is "%(param)s".
        if kwargs:
            for key, value in kwargs.items():
                if value is not None:
                    message = message.replace("%(" + key + ")s", str(value))
                else:
                    message = message.replace("%(" + key + ")s", "'None'")

        # Format standard type parameters.
        if args:
            # Convert tuple to list.
            args = list(args)
            # Travel the list.
            for i, arg in enumerate(args):
                if arg is None:
                    args[i] = "'None'"
                else:
                    args[i] = str(arg)

            # Format the message.
            message %= tuple(args)

        return message

    def __str__(self):
        """
        Show this instance as a string.

        :return:    Return this instance as a string.
        :rtype:     str
        """
        return self.message

    def __repr__(self):
        """
        Show this instance as a string.

        :return:    Return this instance as a string.
        :rtype:     str
        """
        return self.__str__()
