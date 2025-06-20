#!/bin/bash

certs_path=$WR_HOME/CA
conf_file=$WR_HOME/cfg/wr_ser_inst.ini

ser_ca=$certs_path/cacert.pem
ser_key=$certs_path/server.key
ser_cert=$certs_path/server.crt
last_day=2

prepare_certs_path()
{
    if [ ! -d $certs_path ];then
        mkdir -p $certs_path
    fi
    cp /etc/pki/tls/openssl.cnf $certs_path/.
    cd $certs_path; mkdir ./demoCA ./demoCA/newcerts ./demoCA/private
    touch ./demoCA/index.txt
    echo '01'>./demoCA/serial
    chmod 700 ./demoCA/private
    sed -i 's/^.*default_md.*$/default_md      = sha256/' openssl.cnf
}

generate_root_cert()
{
    password=$(openssl rand -base64 32)
    cd $certs_path
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl genrsa -aes256 -passout stdin -out demoCA/private/cakey.pem 2048
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl req -new -x509 -passin stdin -days 10 -key demoCA/private/cakey.pem -out demoCA/cacert.pem -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=CA"
    cp demoCA/cacert.pem .
    #chmod 400 cacert.pem
}

create_server_certs()
{
    mkdir $certs_path/server
    touch $certs_path/server/openssl.cnf
    cd $certs_path
    password=$(openssl rand -base64 32)
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl genrsa -aes256 -passout stdin -out server.key 2048
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl req -new -key server.key -passin stdin -out server.csr -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=server"
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl x509 -req -days 10 -in server.csr -CA demoCA/cacert.pem -CAkey demoCA/private/cakey.pem -passin stdin -CAcreateserial -out server.crt -extfile server/openssl.cnf
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl rsa -in server.key -out server.key -passin stdin
    chmod 400 server.*
}

create_server_conf()
{
    if [ ! -f $conf_file ]; then
        touch $conf_file
    fi
    cat <<EOF > $conf_file
SER_SSL_CA=$ser_ca
SER_SSL_KEY=$ser_key
SER_SSL_CERT=$ser_cert
EOF
}

check_certs_exist()
{
    echo "check certs whether exists"
    if [ ! -f $ser_ca ] || [ ! -f $ser_key ] || [ ! -f $ser_cert ];then
        echo "Please check following server certs whether exist: cacert.pem, server.key, server.crt ."
        set -e
    fi
}

check_certs_permission()
{
    if [ ! -r $ser_ca ] || [ -w $ser_ca ] || [ -x $ser_ca ];then
        chmod 400 $ser_ca
    fi
    if [ ! -r $ser_key ] || [ -w $ser_key ] || [ -x $ser_key ];then
        chmod 400 $ser_key
    fi
    if [ ! -r $ser_cert ] || [ -w $ser_cert ] || [ -x $ser_cert ];then
        chmod 400 $ser_cert
    fi
}

check_certs_expired()
{
    echo "check certs whether expired"
    ca_last=$(openssl x509 -in $ser_ca -noout -enddate | cut -d= -f2 | xargs -I {} date -d {} +%s | xargs -I {} expr {} - $(date +%s) | xargs -I {} expr {} / 86400)
    cert_last=$(openssl x509 -in $ser_cert -noout -enddate | cut -d= -f2 | xargs -I {} date -d {} +%s | xargs -I {} expr {} - $(date +%s) | xargs -I {} expr {} / 86400)
    if [ $ca_last -lt $last_day ];then
        echo "CA will be expired in $ca_last, please renew $ser_ca."
    fi
    if [ $cert_last -lt $last_day ];then
        echo "CA will be expired in $cert_last, please renew $ser_cert."
    fi
}

check_certs()
{
    check_certs_exist
    check_certs_permission
    check_certs_expired
}

main()
{
    prepare_certs_path
    generate_root_cert
    create_server_conf
    generate_root_cert
    create_server_certs
    check_certs
}

main