#!/usr/bin/env python3
import can
import time

# -----------------------------
# CAN FD 配置
# -----------------------------
CAN_INTERFACE = 'can0'
TX_ID = 0x7A7  # 请求发往 ECU
RX_ID = 0x7AF  # ECU 响应
TIMEOUT = 0.5  # 超时
LOG_FILE = "did_ascii.log"

# 建立 CAN 总线
bus = can.interface.Bus(channel=CAN_INTERFACE, bustype='socketcan', fd=True)

# NRC（Negative Response Codes）含义
NRC_CODES = {
    0x10: "General Reject",
    0x11: "Service Not Supported",
    0x12: "Sub-function Not Supported",
    0x13: "Incorrect Message Length",
    0x22: "Conditions Not Correct",
    0x31: "Request Out Of Range",
    0x33: "Security Access Denied",
    0x78: "Response Pending",
    0x7E: "Service Not Supported In Active Session",
    0x7F: "Service Failed",
}

def read_did(did):
    """发送单个 DID 请求，并等待 ECU 响应"""
    data = [0x03, 0x22, (did >> 8) & 0xFF, did & 0xFF]
    while len(data) < 8:
        data.append(0x00)

    msg = can.Message(
        arbitration_id=TX_ID,
        is_extended_id=False,
        is_fd=True,
        bitrate_switch=True,
        data=data
    )

    try:
        bus.send(msg)
        print(f"[TX] 请求 DID 0x{did:04X}: {data}")
    except can.CanError as e:
        print(f"[ERR] 发送失败: {e}")
        return None, None

    start_time = time.time()
    while True:
        remaining = TIMEOUT - (time.time() - start_time)
        if remaining <= 0:
            return None, None
        rx_msg = bus.recv(timeout=remaining)
        if rx_msg and rx_msg.arbitration_id == RX_ID:
            return rx_msg.data, rx_msg

def parse_response(did, data):
    """解析正响应和负响应"""
    if not data:
        return f"DID 0x{did:04X}: 无响应或未支持"

    # 负响应判定: 0x7F + 原始服务码 + NRC
    if data[1] == 0x7F and data[2] == 0x22:
        nrc = data[3]
        reason = NRC_CODES.get(nrc, f"Unknown NRC 0x{nrc:02X}")
        return f"DID 0x{did:04X}: 负响应 - {reason}"

    # 正响应判定: 0x62 + DID
    if data[1] == 0x62 and data[2] == ((did >> 8) & 0xFF) and data[3] == (did & 0xFF):
        payload = data[4:]
        ascii_str = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in payload])
        return f"DID 0x{did:04X}: 正响应 - Data: {payload}, ASCII: {ascii_str}"
 	# 正响应判定: 0x62 + DID
    if data[2] == 0x62 and data[3] == ((did >> 8) & 0xFF) and data[4] == (did & 0xFF):
        payload = data[5:]
        ascii_str = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in payload])
        return f"DID 0x{did:04X}: 正响应 - Data: {payload}, ASCII: {ascii_str}"
    return f"DID 0x{did:04X}: 未知响应 - {data}"

if __name__ == "__main__":
    try:
        with open(LOG_FILE, "a") as log_f:
            for did in range(0x0000, 0xffff):
                data, rx_msg = read_did(did)
                line = parse_response(did, data)
                print(line)
                log_f.write(line + "\n")
    finally:
        bus.shutdown()  # 退出前关闭总线
            
            
