import can
import time

def send_flow_control(bus):
    # 发送流控制帧（示例）
    control_msg = can.Message(arbitration_id=0x7E0, data=[0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id=False)
    bus.send(control_msg)

def read_memory(bus, start_address):
    # 发送流控制帧
    send_flow_control(bus)

    # 读取 0xFF 个地址
    msg = can.Message(arbitration_id=0x7E0, data=[
        0x07, 0x23, 0x14,
        (start_address >> 24) & 0xFF,
        (start_address >> 16) & 0xFF,
        (start_address >> 8) & 0xFF,
        start_address & 0xFF,
        0xFF
    ], is_extended_id=False)
    bus.send(msg)

    all_data = []
    
    # 接收多帧响应
    while True:
        response = bus.recv()
        if response:
            data = response.data
            all_data.extend(data)

            # 保存十六进制数据
            with open("hex_data.txt", "a") as hex_file:
                hex_file.write(' '.join(f"{b:02X}" for b in data) + '\n')

            # 检查是否是最后一帧
            if len(data) < 8:  # 假设最后一帧小于 8 字节
                break

    # 转换为 ASCII
    ascii_string = ''.join(chr(b) for b in all_data if 32 <= b <= 126)
    print(f"Address: {hex(start_address)}, ASCII: {ascii_string}")

def main():
    bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
    start_address = 0xC3F80000

    try:
        while True:
            read_memory(bus, start_address)
            start_address += 0xFF  # 每次加 0xFF
            time.sleep(0.1)  # 适当的延迟，避免发送过快
    except KeyboardInterrupt:
        print("Stopped by user.")

if __name__ == "__main__":
    main()
