#!/bin/bash

certs_path=$WR_HOME/CA
conf_file=$WR_HOME/cfg/wr_cli_inst.ini

cli_ca=$certs_path/cacert.pem
cli_key=$certs_path/client.key
cli_cert=$certs_path/client.crt
cli_crl=$certs_path/client.crl
last_day=2

generate_client_certs()
{
    mkdir $certs_path/client
    touch $certs_path/client/openssl.cnf
    cd $certs_path
    password=$(openssl rand -base64 32)
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl genrsa -aes256 -passout stdin -out client.key 2048
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl req -new -key client.key -passin stdin -out client.csr -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=client"
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl x509 -req -days 10 -in client.csr -CA demoCA/cacert.pem -CAkey demoCA/private/cakey.pem -passin stdin -CAcreateserial -out client.crt -extfile client/openssl.cnf
    export OPENSSL_CONF=$certs_path/openssl.cnf;echo password | openssl rsa -in client.key -out client.key -passin stdin
    chmod 400 client.*
}

create_client_conf()
{
    if [ ! -f $conf_file ]; then
        touch $conf_file
    fi
    cat <<EOF > $conf_file
CLI_SSL_CA=$cli_ca
CLI_SSL_KEY=$cli_key
CLI_SSL_CERT=$cli_cert
CLI_SSL_CRL=$cli_crl
EOF
}

check_certs_exist()
{
    echo "check certs whether exists"
    if [ ! -f $cli_ca ] || [ ! -f $cli_key ] || [ ! -f $cli_cert ];then
        echo "Please check following client certs whether exist: cacert.pem, client.key, client.crt ."
        set -e
    fi
}

check_certs_permission()
{
    if [ ! -r $cli_ca ] || [ -w $cli_ca ] || [ -x $cli_ca ];then
        chmod 400 $cli_ca
    fi
    if [ ! -r $cli_key ] || [ -w $cli_key ] || [ -x $cli_key ];then
        chmod 400 $cli_key
    fi
    if [ ! -r $cli_cert ] || [ -w $cli_cert ] || [ -x $cli_cert ];then
        chmod 400 $cli_cert
    fi
}

check_certs_expired()
{
    echo "check certs whether expired"
    ca_last=$(openssl x509 -in $cli_ca -noout -enddate | cut -d= -f2 | xargs -I {} date -d {} +%s | xargs -I {} expr {} - $(date +%s) | xargs -I {} expr {} / 86400)
    cert_last=$(openssl x509 -in $cli_cert -noout -enddate | cut -d= -f2 | xargs -I {} date -d {} +%s | xargs -I {} expr {} - $(date +%s) | xargs -I {} expr {} / 86400)
    if [ $ca_last -lt $last_day ];then
        echo "CA will be expired in $ca_last, please renew $cli_ca."
    fi
    if [ $cert_last -lt $last_day ];then
        echo "CA will be expired in $cert_last, please renew $cli_cert."
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
    generate_client_certs
    create_client_conf
    check_certs
}

main