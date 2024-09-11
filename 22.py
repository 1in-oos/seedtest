import can
import time

# 定义请求和响应的参数
SERVICE_ID = 0x22  # 诊断服务 22
ADDRESS = 0x7DF  # 广播地址，通常用于请求
ECU_ID = 0x7E8  # 目标 ECU 地址

def create_request():
    """创建诊断服务 22 的请求帧"""
    return [ADDRESS, SERVICE_ID]

def parse_response(response):
    """解析响应数据"""
    if response and len(response) > 1:
        return response[2:]  # 跳过前两个字节
    return []

def main():
    # 设置 CAN 总线
    bus = can.interface.Bus(channel="vcan0", interface="socketcan")

    # 创建请求
    request = create_request()

    while True:
        # 发送请求
        bus.send(can.Message(arbitration_id=ADDRESS, data=request, is_extended_id=False))
        print("发送请求:", request)

        # 等待响应
        time.sleep(0.1)  # 根据实际情况调整延时

        try:
            response = bus.recv(timeout=1.0)  # 接收响应，超时设置为1秒
            if response and response.arbitration_id == ECU_ID:
                fault_codes = parse_response(response.data)
                print("接收到响应:", fault_codes)
            else:
                print("未收到有效响应")
        except can.CanError as e:
            print("CAN 错误:", e)

        # 可根据需要添加退出条件
        # if some_exit_condition:
        #     break

if __name__ == "__main__":
    main()
