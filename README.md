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

pip install python-can

test.py使用卡方分布计算卡方值和P值
观察数据为当前字节在所有组出现次数
实际观测值与理论推断值之间的偏离程度就决定P值大小
卡方值（Chi-square value）： 卡方值是一种衡量观察值与期望值之间偏离程度的统计量。在卡方检验中，我们将观察到的频数与期望的频数进行比较，并计算得到卡方值。卡方值越大表示观察值与期望值之间的偏离程度越大
p 值是在假设检验中用于判断观察到的数据是否与假设模型一致的概率。在卡方检验中，p 值表示在原假设成立的情况下，观察到的数据或更极端情况发生的概率。如果 p 值小于设定的显著性水平（通常为 0.05），则我们有足够的证据拒绝原假设，认为观察到的数据与期望值有显著差异；
如果 p 值大于显著性水平，则我们无法拒绝原假设，认为观察到的数据与期望值没有显著差异。
也就是出现大于==平均值的概率
