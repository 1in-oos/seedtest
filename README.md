uds27认证

安装 CAN 设备需要加载 can_dev 模块并配置 IP 链路以指定 CAN 总线比特率，例如：
modprobe can_dev
modprobe can
modprobe can_raw
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0
还有一个用于测试目的的虚拟CAN驱动程序，可以使用以下命令在Linux中加载和创建。
modprobe can
modprobe can_raw
modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
ip link show vcan0

