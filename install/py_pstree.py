#!/usr/bin/env python3
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
# Description  : py_pstree.py is utility to kill process
#############################################################################

#import psutil
import sys
try:
    import subprocess
    import codecs
    import argparse
except ImportError as e:
    sys.exit("[GAUSS-52200] : Unable to import module: %s." % str(e))


VERSION = '1.0.0'


def command_pstree_parse():
    """
    Parse command line
    """
    parser = argparse.ArgumentParser(description='This script for get list of process.')
    parser.add_argument('-p', '--parents', dest='cpid', required=False,
                        help="Obtain the pid list of parents of given pid")
    parser.add_argument('-c', '--children', dest='ppid', required=False,
                        help="Obtain the children's pid list of given pid")
    parser.add_argument('-s', '--self', dest='include_self', required=False,
                        help='The selection of including the given pid')
    return parser


def parse_args():
    """
    Parse args
    """
    parser = command_pstree_parse()
    opt = parser.parse_args()
    if not (opt.ppid or opt.cpid):
        parser.error('Pid not specified.')
    if (opt.ppid and not opt.ppid.isdigit()) or (opt.cpid and not opt.cpid.isdigit()):
        parser.error('Pid format is incorrect.')
    return opt

def getPidList(opt):
    """
    Get all pid use subprocess command
    """
    pid_list = []

    if opt.cpid:
        cmd = "ps -o ppid= -p {}".format(opt.cpid)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0 and output.strip():
            pid_list = list(map(int, output.strip().split()))
    
    elif opt.ppid:
        cmd = "pgrep -P {}".format(opt.ppid)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status == 0 and output.strip():
            pid_list = list(map(int, output.strip().split()))
        
        if opt.include_self:
            pid_list.insert(0, int(opt.ppid))
    
    pid_list = sorted(list(set(pid_list)))
    return pid_list

if __name__ == "__main__":
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    opts = parse_args()
    pid_list = getPidList(opts)
    for pid in pid_list:
        print(pid)
