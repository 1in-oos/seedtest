import can
import time

def call_service_27(bus):
    # 发送 27 服务请求
    msg = can.Message(arbitration_id=0x7E0, data=[
        0x02
        0x27, 0x01,  # 服务 ID 和子功能
        0x00, 0x00, 0x00, 0x00,0x00  # 其他数据根据需要填充
    ], is_extended_id=False)
    bus.send(msg)
    all_data = []
    # 接收多帧响应
    while True:
        response = bus.recv()
        if response:
            data = response.data
            # 检查是否是最后一帧
            if(data[0] & 0xF0) == 0x00:     # 检查高四位
                all_data=data[3:data[0]]
                break
            elif(data[0] & 0xF0) == 0x10:
                all_data=data[4:]
                data_length= data[1]-data[1]/8-2
                # 发送流控制帧
                fc_msg = can.Message(arbitration_id=0x7E0, data=[0x30, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id=False)
                bus.send(fc_msg)
            elif (data[0] & 0xF0) ==  0x20:  
                all_data.extend(data[1:])

    print(data_length)
    return all_data[:data_length]


def process_seed(seed_data):
    # 这里实现你的算法来处理种子
    # 示例：将数据转为十六进制字符串
    return ''.join(f"{b:02X}" for b in seed_data)

def main():
    bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
    try:
        # 调用 27 服务获取种子
        seed_data = call_service_27(bus)
        if seed_data:
            # 处理种子并获取回复
            seed_response = process_seed(seed_data)
            print(f"Seed Response: {seed_response}")
        else:
            print("No response received.")
    except KeyboardInterrupt:
        print("Stopped by user.")

if __name__ == "__main__":
    main()
