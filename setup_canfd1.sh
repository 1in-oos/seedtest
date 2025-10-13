#!/bin/bash
# ============================================
# CAN0 接口配置脚本 (CAN FD)
# - 仲裁段速率: 500 kbps
# - 数据段速率: 2 Mbps
# - 仲裁段采样点: 0.75
# - 数据段采样点: 0.75
# - 自动重启时间: 1000 ms
# - 发送队列长度: 100000
# ============================================

# 1. 确保 can0 先关闭，避免配置冲突
sudo ip link set can1 down

# 2. 配置 CAN0 参数
#   type can            表示设置为 CAN 接口
#   bitrate             仲裁段波特率 (500 kbps)
#   sample-point        仲裁段采样点 (0.75 = 75%)
#   dbitrate            数据段波特率 (2 Mbps)
#   dsample-point       数据段采样点 (0.75 = 75%)
#   fd on               启用 CAN FD 模式 (ISO FD)
#   restart-ms 1000     接口出错 1000 ms 后自动重启
sudo ip link set can1 type can \
    bitrate 500000 sample-point 0.75 \
    dbitrate 2000000 dsample-point 0.75 \
    fd on restart-ms 1000

# 3. 调整发送队列长度 (默认 10，太小容易丢包)
#   txqueuelen 100000  增大发送队列到 100000
sudo ip link set can1 txqueuelen 100000

# 4. 启动 can0 接口
sudo ip link set can1 up

# 5. 显示配置结果，确认是否生效
ip -details link show can1

