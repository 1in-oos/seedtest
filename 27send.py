import can
import time

# 固定 seed（可改为随机生成）
SEED = [0x12, 0x34, 0x56, 0x78]

# 全局状态：失败计数和锁定标志
failed_attempts = 0
locked = False
MAX_FAILED = 3  # 达到 3 次错误锁定

def pad_to_8(data, pad_byte=0x00):
    """把列表 data 补齐到 8 个字节（如果超过 8，会截断到 8）"""
    if len(data) >= 8:
        return data[:8]
    return data + [pad_byte] * (8 - len(data))

def send_message(bus, arbitration_id, data, pad_byte=0x00):
    """
    发送 CAN 消息，自动补齐到 8 字节。
    data: list[int]
    """
    data8 = pad_to_8(list(data), pad_byte=pad_byte)
    msg = can.Message(arbitration_id=arbitration_id, data=bytearray(data8), is_extended_id=False)
    try:
        bus.send(msg)
    except can.CanError as e:
        print("CAN send error:", e)
    else:
        print(f"Sent {arbitration_id:03X} :", " ".join("{:02X}".format(byte) for byte in data8))

def handle_security_access(bus, request_msg):
    """
    处理 Security Access 0x27 请求
    request_msg.data[2] 为 sub-function (0x01 请求 seed, 0x02 发送 key)
    全局使用 failed_attempts 和 locked 状态
    """
    global failed_attempts, locked

    if len(request_msg.data) < 3:
        return

    subfunc = request_msg.data[2]

    # Request seed
    if subfunc == 0x01:
        # 返回 positive response 0x67, subfunc 0x01, 后面跟 seed
        response = [len(SEED) + 2, 0x67, 0x01] + SEED
        send_message(bus, 0x7E8, response)
        print("Sent seed to client:", " ".join(f"{b:02X}" for b in SEED))
        return

    # Send key
    if subfunc == 0x02:
        # 如果当前被锁定，回复否定响应（NRC=0x36）
        if locked:
            # 0x7F, service, NRC
            resp = [0x03, 0x7F, 0x27, 0x36]
            send_message(bus, 0x7E8, resp)
            print("Locked: deny key attempt (NRC 36).")
            return

        # 提取 key（从 byte 3 开始），注意 padding
        key = list(request_msg.data[3:3 + len(SEED)])
        expected_key = [~b & 0xFF for b in SEED]  # 这里算法为按位取反

        if key == expected_key:
            # 正响应：0x67 0x02 + key
            response = [len(key) + 2, 0x67, 0x02] + key
            send_message(bus, 0x7E8, response)
            print("Key correct, access granted")
            # 成功则重置失败计数
            failed_attempts = 0
        else:
            # 错误：增加失败计数，视情况锁定并返回 NRC 0x36 (invalid key) 或 0x33
            failed_attempts += 1
            print(f"Key incorrect ({failed_attempts}/{MAX_FAILED}). Expected:",
                  " ".join(f"{b:02X}" for b in expected_key))
            # 返回 invalid key NRC (0x33)
            resp = [0x03, 0x7F, 0x27, 0x33]
            send_message(bus, 0x7E8, resp)

            # 达到阈值则进入 locked
            if failed_attempts >= MAX_FAILED:
                locked = True
                print("Reached max failed attempts. Server is now LOCKED.")
        return

    # 不支持的 sub-function -> negative response 0x12
    response = [0x03, 0x7F, 0x27, 0x12]
    send_message(bus, 0x7E8, response)
    print(f"Sub-function {subfunc:02X} not supported")

def handle_ecu_reset(bus, request_msg):
    """
    处理 ECU Reset (0x11)
    如果 subfunc == 0x01，执行“复位解锁”：清除失败计数并解锁，返回 positive response 0x51 0x01
    """
    global failed_attempts, locked
    if len(request_msg.data) < 3:
        return

    subfunc = request_msg.data[2]
    if subfunc == 0x01:
        # reset: 清零失败计数并解锁
        failed_attempts = 0
        locked = False
        # 返回 positive response for ECU Reset: 0x11 + 0x40 = 0x51
        response = [0x02, 0x51, 0x01]  # 没有额外 payload
        send_message(bus, 0x7E8, response)
        print("Received ECU Reset (11 01). State reset and unlocked.")
    else:
        # 不支持的 subfunc -> negative response
        resp = [0x03, 0x7F, 0x11, 0x12]
        send_message(bus, 0x7E8, resp)
        print(f"ECU Reset subfunc {subfunc:02X} not supported")

def main():
    bus = can.interface.Bus(channel='can0', interface='socketcan')
    print("UDS Security Access 0x27 server running (padding frames to 8 bytes)...")
    print("Max failed attempts before lock:", MAX_FAILED)

    try:
        while True:
            msg = bus.recv(timeout=0.1)
            if msg is None:
                continue

            # 调试打印接收的帧
            print("Recv {:03X}:".format(msg.arbitration_id), " ".join("{:02X}".format(b) for b in msg.data))

            # ECU Reset (0x11)
            if msg.arbitration_id == 0x7E0 and len(msg.data) >= 2 and msg.data[1] == 0x11:
                handle_ecu_reset(bus, msg)
                continue

            # Security Access (0x27)
            if msg.arbitration_id == 0x7E0 and len(msg.data) >= 3 and msg.data[1] == 0x27:
                handle_security_access(bus, msg)
                continue

            # 其他请求：可在此扩展
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        bus.shutdown()

if __name__ == "__main__":
    main()
