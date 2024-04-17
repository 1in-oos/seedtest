import can
import time

def send_message(bus, data):
    # 构造要发送的消息
    msg = can.Message(arbitration_id=0x7d9, data=data)
    bus.send(msg)
    print("Sent message:", " ".join("{:02X}".format(byte) for byte in msg.data))

def receive_response(bus):
    while True:
        msg = bus.recv(timeout=0.01)
        if msg is not None and msg.arbitration_id == 0x7d1 and msg.data[1] == 0x27:
            # 发送第一个响应消息
            send_message(bus, [0x10, 0x12, 0x67, 0x01, 0x2C, 0xF5, 0xBA, 0xFB])
            # 等待接收到流控制帧
            while True:
                msg = bus.recv(timeout=0.001)

                if msg is not None and msg.arbitration_id == 0x7d1 and msg.data[0] == 0x30:
                    # 发送第二个和第三个响应消息
                    send_message(bus, [0x21, 0x18, 0x71, 0x56, 0x07, 0x31, 0x32, 0x33])
                    send_message(bus, [0x22, 0x34, 0x35, 0x36, 0x37, 0x38, 0xAA, 0xAA])
                    break
def main():
    # 创建 CAN 总线接口
    bus = can.interface.Bus(channel='can0', bustype='socketcan')
    
    # 循环监听 CAN 总线并处理消息
    try:
        receive_response(bus)
    except KeyboardInterrupt:
        # 捕获 Ctrl+C 中断信号
        print("Exiting...")
    finally:
        # 关闭 CAN 总线接口
        bus.shutdown()

if __name__ == "__main__":
    main()

