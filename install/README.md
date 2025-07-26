安装步骤：
1.root用户创建互信

2.root用户执行预安装
./gs_om preinstall 1p1s_bak.xml lll /home/lll/script/ENVFILE

3.安装用户lll创建互信
./trust.sh hostfile

4.wr安装（待添加最新版证书生成）
source /home/lll/script/ENVFILE
./gs_om wr_install 1p1s_bak.xml WR.tar.gz

5.cm安装（CM告警需求合入之前的CM版本）
./cm_install -X /home/lll/script/1p1s_bak.xml -e /home/lll/script/ENVFILE --cmpkg=/home/lll/script/pkg/openGauss-CM-7.0.0-RC2-openEuler20.03-aarch64.tar.gz

6.卸载
安装用户lll执行
source /home/lll/script/ENVFILE
./gs_om wr_uninstall /home/lll/script/1p1s_bak.xml

