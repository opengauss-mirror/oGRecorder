#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd
# oGRecorder is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


ENABLE_WORM=0
AUTO_TEST=0

for arg in "$@"; do
    if [ "$arg" == "-w" ]; then
        ENABLE_WORM=1
    elif [ "$arg" == "-t" ]; then
        AUTO_TEST=1
    fi
done

cmake -DENABLE_WORM=${ENABLE_WORM} -DAUTO_TEST=${AUTO_TEST} .
make