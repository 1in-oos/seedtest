#!/usr/bin/env python3
import can
import time
import random

def loop_send(interface="can0"):
    # 打开 CAN FD 总线
    bus = can.interface.Bus(
        channel=interface,
        interface="socketcan",
        fd=True   # 关键：启用 CAN FD
    )

    print("开始循环发送 0x4FF 报文，每 400ms 一次...")

    while True:
        # 随机 8 字节数据
        data = [random.randint(0, 255) for _ in range(8)]

        msg = can.Message(
            arbitration_id=0x4FF,
            is_extended_id=False,   # 标准帧
            is_fd=True,             # FD 帧
            bitrate_switch=True,    # 启用 BRS
            data=data
        )

        try:
            bus.send(msg)
            print(f"发送: ID=0x4FF, Data={data}")
        except can.CanError as e:
            print(f"发送失败: {e}")

        time.sleep(0.4)  # 400 ms

if __name__ == "__main__":
    loop_send("can0")
