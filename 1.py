import can
import time

# CAN 通道
channel = 'vcan0'

# 发送和接收 ID
TX_ID = 0x123
RX_ID = 0x456

# 创建 CAN 总线接口
bus = can.interface.Bus(channel=channel, bustype='socketcan')

def send_iso_tp_message(data, tx_id=TX_ID):
    """发送 ISO-TP 消息"""
    max_single_frame_size = 7  # ISO-TP 单帧数据的最大长度（不包括数据头）
    
    if len(data) <= max_single_frame_size:
        # 发送单帧
        can_id = tx_id
        can_data = bytearray([0x00 | len(data)] + list(data))  # 构造单帧数据
        # 填充到 8 字节
        while len(can_data) < 8:
            can_data.append(0x00)  # 以 0x00 填充，或根据协议需要使用其他值	
        message = can.Message(arbitration_id=can_id, data=can_data, is_extended_id=False)
        bus.send(message)  # 发送单帧消息
    else:
        # 发送多帧
        can_id = tx_id
        ff_dl = len(data) + len(data)//7  # 总数据长度
        ff_data = data[:6]  # 首帧数据（最多 6 字节）
        can_data = bytearray([0x10 | (ff_dl >> 8), ff_dl & 0xFF] + list(ff_data))  # 构造首帧数据
        message = can.Message(arbitration_id=can_id, data=can_data, is_extended_id=False)
        bus.send(message)  # 发送首帧消息

        # 流控帧接收
        flow_control_message = bus.recv(timeout=1.0)  # 接收流控帧
        if flow_control_message is None or flow_control_message.arbitration_id != RX_ID:
            print("流控帧接收失败")
            return
        
        block_size = flow_control_message.data[1]  # 流控帧的区块大小
        st_min = flow_control_message.data[2]  # 流控帧的最小分隔时间

        remaining_data = data[6:]  # 剩余数据
        frame_id = 1  # 帧 ID 初始化

        while remaining_data:
            cf_data = remaining_data[:7]  # 每帧的数据（最多 7 字节）
            remaining_data = remaining_data[7:]  # 更新剩余数据
            can_data = bytearray([0x20 | frame_id] + list(cf_data))  # 构造连续帧数据
            while len(can_data) < 8:
            	can_data.append(0x00)  # 以 0x00 填充，或根据协议需要使用其他值	
            message = can.Message(arbitration_id=can_id, data=can_data, is_extended_id=False)
            bus.send(message)  # 发送连续帧消息
            frame_id = (frame_id + 1) % 16  # 更新帧 ID
            time.sleep(st_min / 1000)  # 等待流控帧中指定的时间

def receive_iso_tp_message(rx_id=RX_ID):
    """接收 ISO-TP 消息"""
    first_frame = bus.recv(timeout=1.0)  # 接收首帧
    if first_frame is None or first_frame.arbitration_id != rx_id:
        print("未接收到首帧")
        return

    if first_frame.data[0] >> 4 == 0x0:
        # 单帧
        length = first_frame.data[0] & 0x0F  # 数据长度
        data = first_frame.data[1:length+1]  # 获取数据
        return data
    elif first_frame.data[0] >> 4 == 0x1:
        # 首帧
        length = ((first_frame.data[0] & 0x0F) << 8) + first_frame.data[1]  # 数据总长度
        data = first_frame.data[2:8]  # 获取首帧数据
        # 发送流控帧
        flow_control_data = bytearray([0x30, 0x00, 0x0A])  # 构造流控帧数据
        flow_control_message = can.Message(arbitration_id=TX_ID, data=flow_control_data, is_extended_id=False)
        bus.send(flow_control_message)  # 发送流控帧

        while len(data) < length:
            consecutive_frame = bus.recv(timeout=1.0)  # 接收连续帧
            if consecutive_frame is None or consecutive_frame.arbitration_id != rx_id:
                print("未接收到连续帧")
                return
            data += consecutive_frame.data[1:]  # 更新数据

        return data[:length]  # 返回完整数据

# 发送示例数据
send_data = bytearray([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22])
send_iso_tp_message(send_data)

# 接收示例数据
received_data = receive_iso_tp_message()
print("接收到的数据:", received_data)
