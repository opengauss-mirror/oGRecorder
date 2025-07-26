#!/bin/bash
# 全集群SSH互信自动化配置脚本
# 功能：在单节点执行后，自动配置所有节点间的双向无密码登录
# 使用方法：./cluster_ssh_trust.sh <节点列表文件>

set -eo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 参数检查
if [ $# -ne 1 ]; then
    echo -e "${RED}Usage: $0 <hosts_file>${NC}"
    echo -e "${YELLOW}Example: $0 ./hosts.list${NC}"
    echo "hosts.list 格式示例："
    echo "node1"
    echo "192.168.1.2"
    echo "# 注释行会被忽略"
    exit 1
fi

HOSTS_FILE=$1
SSH_PORT=22
CURRENT_USER=$(whoami)
KEY_TYPE="ed25519"
TMP_DIR="/tmp/ssh_trust_$(date +%s)"
ADMIN_NODE=$(hostname)

# 检查依赖项
check_dependencies() {
    local missing=()
    for cmd in ssh ssh-keygen ssh-keyscan rsync; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}缺失必要组件: ${missing[*]}${NC}"
        exit 1
    fi
}

# 检查hosts文件
validate_hosts_file() {
    if [ ! -f "$HOSTS_FILE" ]; then
        echo -e "${RED}错误: 主机列表文件 $HOSTS_FILE 不存在!${NC}"
        exit 1
    fi

    # 获取有效主机列表（去重排序）
    HOSTS=$(grep -v '^#' "$HOSTS_FILE" | grep -v '^$' | awk '{print $1}' | sort -u)
    
    if [ -z "$HOSTS" ]; then
        echo -e "${RED}错误: 主机列表文件中没有有效的主机!${NC}"
        exit 1
    fi

    # 检查是否包含本地节点
    if ! echo "$HOSTS" | grep -q "^${ADMIN_NODE}$"; then
        echo -e "${YELLOW}警告: 主机列表未包含当前节点($ADMIN_NODE)，自动添加...${NC}"
        HOSTS=$(echo -e "${ADMIN_NODE}\n${HOSTS}" | sort -u)
    fi
}

# 生成SSH密钥
generate_ssh_key() {
    local host=$1
    echo -e "${GREEN}[${host}] 生成SSH密钥...${NC}"
    
    if [ "$host" = "$ADMIN_NODE" ]; then
        # 本地节点
        if [ ! -f ~/.ssh/id_${KEY_TYPE} ]; then
            ssh-keygen -t $KEY_TYPE -f ~/.ssh/id_${KEY_TYPE} -N "" -q
            echo -e "${GREEN}[${host}] SSH密钥已生成${NC}"
        else
            echo -e "${YELLOW}[${host}] 已有SSH密钥，跳过生成${NC}"
        fi
    else
        # 远程节点
        ssh -p $SSH_PORT $CURRENT_USER@$host \
            "if [ ! -f ~/.ssh/id_${KEY_TYPE} ]; then \
                ssh-keygen -t ${KEY_TYPE} -f ~/.ssh/id_${KEY_TYPE} -N \"\" -q; \
                echo 'SSH密钥已生成'; \
            else \
                echo '已有SSH密钥，跳过生成'; \
            fi"
    fi
}

# 收集所有公钥
collect_public_keys() {
    mkdir -p $TMP_DIR
    rm -f $TMP_DIR/*
    
    echo -e "${GREEN}收集所有节点公钥...${NC}"
    
    for host in $HOSTS; do
        echo -e "[${host}] 获取公钥..."
        if [ "$host" = "$ADMIN_NODE" ]; then
            cp ~/.ssh/id_${KEY_TYPE}.pub $TMP_DIR/${host}.pub
        else
            scp -P $SSH_PORT $CURRENT_USER@$host:~/.ssh/id_${KEY_TYPE}.pub $TMP_DIR/${host}.pub 2>/dev/null || \
            echo -e "${RED}[${host}] 警告: 获取公钥失败${NC}"
        fi
    done
}

# 分发公钥和known_hosts
distribute_keys() {
    # 合并所有公钥
    cat $TMP_DIR/*.pub > $TMP_DIR/all_public_keys
    
    # 生成known_hosts
    > $TMP_DIR/known_hosts
    for host in $HOSTS; do
        ssh-keyscan -p $SSH_PORT -H $host >> $TMP_DIR/known_hosts 2>/dev/null
    done
    
    echo -e "${GREEN}开始分发公钥和known_hosts...${NC}"
    
    for host in $HOSTS; do
        echo -e "[${host}] 配置中..."
        
        if [ "$host" = "$ADMIN_NODE" ]; then
            # 本地节点
            cat $TMP_DIR/all_public_keys >> ~/.ssh/authorized_keys
            cat $TMP_DIR/known_hosts >> ~/.ssh/known_hosts
            chmod 600 ~/.ssh/authorized_keys
        else
            # 远程节点
            scp -P $SSH_PORT $TMP_DIR/all_public_keys $TMP_DIR/known_hosts $CURRENT_USER@$host:~/ 2>/dev/null
            ssh -p $SSH_PORT $CURRENT_USER@$host \
                "mkdir -p ~/.ssh; \
                 cat ~/all_public_keys >> ~/.ssh/authorized_keys; \
                 cat ~/known_hosts >> ~/.ssh/known_hosts; \
                 rm -f ~/all_public_keys ~/known_hosts; \
                 chmod 700 ~/.ssh; \
                 chmod 600 ~/.ssh/authorized_keys"
        fi
        
        echo -e "[${host}] 配置完成"
    done
}

# 验证互信
verify_connection() {
    echo -e "${GREEN}验证节点间互信...${NC}"
    
    for src_host in $HOSTS; do
        for dst_host in $HOSTS; do
            [ "$src_host" = "$dst_host" ] && continue
            
            echo -n "[$src_host → $dst_host] 测试..."
            
            if [ "$src_host" = "$ADMIN_NODE" ]; then
                # 从本地节点测试
                if ssh -p $SSH_PORT $CURRENT_USER@$dst_host "echo -n" &>/dev/null; then
                    echo -e "${GREEN}成功${NC}"
                else
                    echo -e "${RED}失败${NC}"
                fi
            else
                # 通过远程节点测试
                if ssh -p $SSH_PORT $CURRENT_USER@$src_host \
                    "ssh -p $SSH_PORT $CURRENT_USER@$dst_host echo -n" &>/dev/null; then
                    echo -e "${GREEN}成功${NC}"
                else
                    echo -e "${RED}失败${NC}"
                fi
            fi
        done
    done
}

# 清理临时文件
cleanup() {
    rm -rf $TMP_DIR
    echo -e "${GREEN}临时文件已清理${NC}"
}

# 主流程
main() {
    check_dependencies
    validate_hosts_file
    
    echo -e "\n${GREEN}=== 开始配置集群SSH互信 ===${NC}"
    echo -e "管理节点: ${YELLOW}${ADMIN_NODE}${NC}"
    echo -e "集群节点: ${YELLOW}$(echo $HOSTS | tr '\n' ' ')${NC}\n"
    
    # 1. 在所有节点生成密钥
    for host in $HOSTS; do
        generate_ssh_key $host
    done
    
    # 2. 收集公钥
    collect_public_keys
    
    # 3. 分发配置
    distribute_keys
    
    # 4. 验证
    verify_connection
    
    # 5. 清理
    cleanup
    
    echo -e "\n${GREEN}=== 全集群SSH互信配置完成 ===${NC}"
    echo -e "所有节点间现在可以无密码登录"
    echo -e "验证命令示例: ${YELLOW}ssh ${CURRENT_USER}@node1${NC}"
}

main