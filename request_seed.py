import can
import time
import signal
import sys

def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting...")
    sys.exit(0)

def extended_session(arb_id, is_extend_id):
    # 发送进入扩展会话的CAN消息
    enter_extended_session = can.Message(arbitration_id=arb_id, data=[0x02, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id=is_extend_id)
    bus.send(enter_extended_session)
 
def request_seed(bus, arb_id, data, is_extend_id):
    # 构造请求种子的CAN消息
    seed_request = can.Message(arbitration_id=arb_id, data=data, is_extended_id = is_extend_id)
    # 发送请求种子的CAN消息
    bus.send(seed_request)
    print("sendrequest")     
    # 接收种子响应
    response = []
    # 检查消息的ID是否是发送ID加8或者是交换ID的后两个字节 
    expected_response_ids = {arb_id + 8, arb_id - 8, (arb_id & 0xFFFF0000) | ((arb_id & 0x0000FF00) >> 8) | ((arb_id & 0x000000FF) << 8)}
    #print("Hexadecimal:", [hex(num) for num in expected_response_ids])
    while True:
        msg = bus.recv()
        if msg is None:
            break 

        if msg.arbitration_id in expected_response_ids and (msg.data[1]==0x67 or msg.data[2]==0x67):
            response.append(msg)
            #response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)
            #print("Response data:", response_data)
            break
    #print("结束第一个循环")        
    if response:
        # 解析响应数据
        response_data = " ".join("{:02X}".format(byte) for byte in response[0].data)

        if response[0].data[0] >> 4 == 0b0000:
            if response[0].data[1] == 0x7F:
                print("Request failed. Response data:", response_data)
                return
            # 检查第二字节+0x40是否等于接收到的第二字节
            expected_next_seq = (data[1] + 0x40) & 0xFF
            if response[0].data[1] == expected_next_seq:
                # 计算种子长度
                data_length = (response[0].data[0] & 0x0F) 
                # 从响应消息中提取指定长度的数据字节，每行从第二个字节开始，跳过每行的第一个字节
                seed = [byte for msg in response for byte in msg.data][3:data_length+1]
                
                print("seed_length", data_length, "Seed:", " ".join("{:02X}".format(byte) for byte in seed))     
            else:
                print("Request failed. Response data:", response_data)                
        # 判断响应数据的第一字节前四位是否为1
        elif response[0].data[0] >> 4 == 0b0001:
            # 发送流控制帧
            flow_control_frame = can.Message(arbitration_id=arb_id, data=[0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id = is_extend_id)
            bus.send(flow_control_frame)

            print("发送流控制")
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
            #print("结束第二个循环")    
            # 检查第二字节+0x40是否等于接收到的第三字节
            expected_next_seq = (data[1] + 0x40) & 0xFF
            if response[0].data[2] == expected_next_seq:
                # 计算种子长度
                data_length = (response[0].data[0] & 0x0F) << 8 | response[0].data[1]
                # 从响应消息中提取指定长度的数据字节，每行从第二个字节开始，跳过每行的第一个字节
                seed = [byte for msg in response for i, byte in enumerate(msg.data) if i % 8 != 0][3:data_length+1]
                log_file = "seed.log"  # 日志文件名
                with open(log_file, "a") as f:
                    f.write(" ".join("{:02X}".format(byte) for byte in seed) + "\n")  # 将seed内容写入日志文件
                    #f.write("\n")  # 每次写入后加入一个回车符以进行分隔
                print("seed_length", data_length, "Seed:", " ".join("{:02X}".format(byte) for byte in seed))

            else:
                print("Request failed. Response data:", response_data)
        else:
            print("第一次见")
    else:
        print("no Response")
                           
# 获取用户输入的CAN消息ID和数据字节
id_input = input("Enter CAN message ID (hex, leave empty to use default 7e1): ").strip()
if id_input:
    arb_id = int(id_input, 16)
else:
    arb_id = 0x7e1

data_input = input("Enter data bytes (hex, leave empty to use default 02 27 01, separated by spaces): ").strip()
if data_input:
    data = [int(byte, 16) for byte in data_input.split()]
else:
    data = [0x02, 0x27, 0x01]
expected_response_ids =  (arb_id & 0xFFFF0000) | ((arb_id & 0x0000FF00) >> 8) | ((arb_id & 0x000000FF) << 8)
is_extend_id = arb_id > 0x7FF
# 将数据字节补齐到8个字节
data.extend([0] * (8 - len(data)))
#id过滤
filters = [
    {"can_id": arb_id+8, "can_mask": 0x7FF, "extended": False},
    {"can_id": arb_id-8, "can_mask": 0x7FF, "extended": False},
    {"can_id": expected_response_ids, "can_mask": 0x1FFFFFFF, "extended": True},
    {"can_id": arb_id, "can_mask": 0x1FFFFFFF, "extended": True},
]

bus = can.interface.Bus(channel="can0", interface="socketcan", can_filters=filters)

# 创建CAN总线接口
bus = can.interface.Bus(channel='can0', bustype='socketcan')

# 注册信号处理程序
signal.signal(signal.SIGINT, signal_handler)

try:
    # 请求2000次种子
    for i in range(2000):
        print("Requesting seed", i + 1)
        extended_session(arb_id, is_extend_id)
        time.sleep(0.1)
        request_seed(bus, arb_id, data, is_extend_id)
        time.sleep(0.1)  # 间隔一段时间再发送下一个请求，以避免发送速率过快

except KeyboardInterrupt:
    print("\nCtrl+C detected. Exiting...")

finally:
    # 关闭CAN总线接口
    bus.shutdown()


