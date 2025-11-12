#!/usr/bin/env python3
import can
import time
import threading


def send_periodic_diag(bus, interval=1.0):
    """周期性发送 0x7a7 报文"""
    diag_data = [0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    msg = can.Message(
        arbitration_id=0x7a7,
        is_extended_id=False,
        is_fd=True,
        bitrate_switch=True,
        data=diag_data
    )
    while True:
        try:
            bus.send(msg)
            print(f"[TX] 发送诊断激活报文 ID=0x{msg.arbitration_id:X}, Data={diag_data}")
        except can.CanError as e:
            print(f"[ERR] 发送失败: {e}")
        time.sleep(interval)

def monitor_response(bus, timeout=1, expected_id=0x7AF):
    """监听 ECU 状态响应——判断是否为 expected_id 且 payload 以 expected_payload 开头"""
    expected_payload = bytes.fromhex('065001')  # 更清晰的定义方式
    log_file = "ecu_status.log"
    print(f"监听期望: ID=0x{expected_id:X}, Payload starts with {expected_payload.hex()}")
    misses = 0
    while True:
        msg = bus.recv(timeout=timeout)
        if msg:
            payload = bytes(msg.data)
            if msg.arbitration_id == expected_id and payload.startswith(expected_payload):
                log_line = f"[OK] 收到期望应答: ID=0x{msg.arbitration_id:X}, Data={payload.hex()}\n"
                misses = 0
                print(log_line, end="")
                with open(log_file, "a") as f:
                    f.write(log_line)
            else:
                print(f"[RX] 其他报文: ID=0x{msg.arbitration_id:X}, Data={payload.hex()}")
        else:
            print("[WARN] 未收到 ECU 响应，可能死机/异常")
            misses += 1
            log_line = "[WARN] 未收到 ECU 响应，可能死机/异常\n"
            with open(log_file, "a") as f:  
                f.write(log_line)        
def fuzzing_send(bus, interval=0.05):
    """模糊测试数据注入"""
    import random
    while True:
        rand_data = [random.randint(0, 255) for _ in range(64)]
        fuzz_msg = can.Message(
            arbitration_id=random.randint(0x100, 0x7FF),
            is_extended_id=False,
            is_fd=True,
            bitrate_switch=True,
            data=rand_data
        )
        try:
            bus.send(fuzz_msg)
            print(f"[Fuzz] 发送随机帧 ID=0x{fuzz_msg.arbitration_id:X}, Data={rand_data}")
        except can.CanError:
            pass
        time.sleep(interval)


if __name__ == "__main__":
    bus = can.interface.Bus(
    channel="can0",
    interface="socketcan",
    fd=True,
    can_filters=[{"can_id": 0x7AF, "can_mask": 0x7FF}]
)

    # 启动线程
    threading.Thread(target=send_periodic_diag, args=(bus, 1.0), daemon=True).start()
    threading.Thread(target=monitor_response, args=(bus,), daemon=True).start()
    threading.Thread(target=fuzzing_send, args=(bus,), daemon=True).start()

    while True:
        time.sleep(1)
