# udstest.py - 修改版，添加诊断数据发送和ID输入功能
import can
import time
import signal
import sys
import random
from typing import Optional, List, Tuple
# 在文件顶部添加导入
import threading

# 在全局变量区域添加
keep_session_alive = False
alive_check_thread = None

# 添加会话保持函数
def session_keep_alive(bus, arb_id, expected_response_ids, is_extend_id):
    """会话保持线程函数"""
    global keep_session_alive
    while keep_session_alive:
        try:
            # 发送Tester Present (3E 00)
            send_iso_tp_message(bus, arb_id, expected_response_ids, [0x3E, 0x00], is_extend_id)
            # 等待响应但不处理
            receive_iso_tp_message(bus, arb_id, expected_response_ids)
            # 每5秒发送一次
            time.sleep(5)
        except Exception as e:
            if keep_session_alive:
                print(f"⚠️  会话保持出错: {e}")
            break

def start_session_keep_alive(bus, arb_id, expected_response_ids, is_extend_id):
    """启动会话保持"""
    global keep_session_alive, alive_check_thread
    if not keep_session_alive:
        keep_session_alive = True
        alive_check_thread = threading.Thread(target=session_keep_alive, args=(bus, arb_id, expected_response_ids, is_extend_id), daemon=True)
        alive_check_thread.start()
        print("✅ 会话保持已启动")

def stop_session_keep_alive():
    """停止会话保持"""
    global keep_session_alive, alive_check_thread
    if keep_session_alive:
        keep_session_alive = False
        if alive_check_thread:
            alive_check_thread.join(timeout=1)
        print("⏹️  会话保持已停止")

# 在 get_arbitration_id 函数后添加
def get_target_address():
    """获取目标地址（用于诊断激活）"""
    target_input = input("🔧 输入目标逻辑地址 (hex, 如: 0101): ").strip()
    if target_input:
        try:
            return int(target_input, 16)
        except ValueError:
            print("❌ 地址格式错误，使用默认地址")
    return None

# 修改 interactive_mode 函数，添加新命令
def interactive_mode(bus, arb_id, expected_response_ids, is_extend_id):
    """交互式诊断模式"""
    print("\n🎮 进入交互式诊断模式")
    print("支持的命令:")
    print("  send        - 发送自定义诊断数据")
    print("  session X   - 切换到诊断会话 (如: session 03)")
    print("  seed LEVEL  - 请求安全访问种子 (如: seed 01)")
    print("  reset       - ECU硬重置")
    print("  keepalive   - 启动/停止会话保持")
    print("  activate    - 发送诊断激活请求")
    print("  help        - 显示帮助信息")
    print("  quit/exit   - 退出程序")
    print("-" * 50)
    
    while True:
        try:
            cmd = input("\n🔧 UDS> ").strip().lower()
            
            if cmd in ['quit', 'exit', 'q']:
                print("👋 退出程序")
                stop_session_keep_alive()  # 退出前停止会话保持
                break
                
            if cmd == 'help':
                print("\n📖 帮助信息:")
                print("  send        - 发送自定义诊断数据")
                print("  session X   - 切换诊断会话 (X: 01/02/03)")
                print("  seed LEVEL  - 请求安全种子 (LEVEL: 01/03/05等)")
                print("  reset       - ECU硬重置")
                print("  keepalive   - 启动/停止会话保持")
                print("  activate    - 发送诊断激活请求")
                print("  help        - 显示此帮助")
                print("  quit/exit   - 退出程序")
                continue
                
            if cmd == 'send':
                send_custom_diagnostic_data(bus, arb_id, expected_response_ids, is_extend_id)
                continue
                
            if cmd == 'keepalive':
                global keep_session_alive
                if keep_session_alive:
                    stop_session_keep_alive()
                else:
                    start_session_keep_alive(bus, arb_id, expected_response_ids, is_extend_id)
                continue
                
            if cmd == 'activate':
                target_addr = get_target_address()
                if target_addr:
                    # 发送诊断激活请求 (DOIP 协议格式示例)
                    activation_req = [0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07,
                                    (arb_id >> 8) & 0xFF, arb_id & 0xFF,
                                    (target_addr >> 8) & 0xFF, target_addr & 0xFF,
                                    0x00, 0x00, 0x00, 0x00]
                    print(f"📤 发送诊断激活请求: {' '.join(f'{b:02X}' for b in activation_req)}")
                else:
                    print("❌ 未提供目标地址")
                continue
                
            if cmd.startswith('session '):
                try:
                    session_type = int(cmd.split()[1], 16)
                    print(f"🔄 切换到诊断会话 0x{session_type:02X}")
                    send_iso_tp_message(bus, arb_id, expected_response_ids, [0x10, session_type], is_extend_id)
                    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
                    if response:
                        print(f"📥 响应: {' '.join(f'{b:02X}' for b in response)}")
                except Exception as e:
                    print(f"❌ 命令格式错误: {e}")
                continue
                
            if cmd.startswith('seed '):
                try:
                    level = int(cmd.split()[1], 16)
                    print(f"🔑 请求安全访问种子 (级别: 0x{level:02X})")
                    request_seed(bus, arb_id, expected_response_ids, level, is_extend_id, 1)
                except Exception as e:
                    print(f"❌ 命令格式错误: {e}")
                continue
                
            if cmd == 'reset':
                print("🔄 执行ECU硬重置")
                send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
                response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
                if response:
                    print(f"📥 响应: {' '.join(f'{b:02X}' for b in response)}")
                continue
                
            if cmd:
                print("❌ 未知命令，输入 'help' 查看帮助")
                
        except KeyboardInterrupt:
            print("\n👋 收到中断信号，退出...")
            stop_session_keep_alive()  # 退出前停止会话保持
            break
        except EOFError:
            print("\n👋 输入结束，退出...")
            stop_session_keep_alive()  # 退出前停止会话保持
            break
# 补充
def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting...")
    sys.exit(0)

def Save_log(seed):
    log_file = "seed.log"
    hex_seed = ' '.join(f'{b:02X}' for b in seed)

    with open(log_file + "_hex", "a") as f_hex:
        f_hex.write(hex_seed + '\n')

def send_iso_tp_message(bus, arb_id, expected_response_ids, data, is_extend_id):
    """发送 ISO-TP 消息，支持CAN和CAN FD"""
    is_fd = hasattr(bus, '_can_protocol') and bus._can_protocol == can.CanProtocol.CAN_FD
    max_single_frame_size = 62 if is_fd else 7
    
    if len(data) <= max_single_frame_size:
        can_id = arb_id
        can_data = bytearray([0x00 | len(data)] + list(data))
        
        if not is_fd:
            while len(can_data) < 8:
                can_data.append(0x00)
        
        message = can.Message(
            arbitration_id=can_id, 
            data=can_data, 
            is_extended_id=is_extend_id,
            is_fd=is_fd,
            bitrate_switch=is_fd
        )
        bus.send(message)
    else:
        can_id = arb_id
        ff_dl = len(data)
        ff_data = data[:62] if is_fd else data[:6]
        can_data = bytearray([0x10 | (ff_dl >> 8), ff_dl & 0xFF] + list(ff_data))
        
        message = can.Message(
            arbitration_id=can_id, 
            data=can_data, 
            is_extended_id=is_extend_id,
            is_fd=False
        )
        bus.send(message)

        flow_control_message = bus.recv(timeout=1.0)
        if flow_control_message is None or flow_control_message.arbitration_id not in expected_response_ids or flow_control_message.data[0] >> 4 != 0x3:
            print("流控帧接收失败")
            return
        
        block_size = flow_control_message.data[1]
        st_min = flow_control_message.data[2]

        remaining_data = data[62 if is_fd else 6:]
        frame_id = 1

        while remaining_data:
            max_cf_size = 63 if is_fd else 7
            cf_data = remaining_data[:max_cf_size]
            remaining_data = remaining_data[max_cf_size:]
            can_data = bytearray([0x20 | frame_id] + list(cf_data))
            
            if not is_fd:
                while len(can_data) < 8:
                    can_data.append(0x55)
            
            message = can.Message(
                arbitration_id=can_id, 
                data=can_data, 
                is_extended_id=is_extend_id,
                is_fd=False
            )
            bus.send(message)
            frame_id = (frame_id + 1) % 16
            time.sleep(st_min / 1000)

def receive_iso_tp_message(bus, arb_id, expected_response_ids):
    """接收 ISO-TP 消息，支持CAN和CAN FD"""
    while True:
        first_frame = bus.recv(timeout=1.0)
        if first_frame is None or first_frame.arbitration_id not in expected_response_ids:
            print("未接收到首帧")
            continue

        is_fd = getattr(first_frame, 'is_fd', False)

        if first_frame.data[0] >> 4 == 0x0:
            length = first_frame.data[0] & 0x0F
            data = first_frame.data[1:length+1]
            return data
        elif first_frame.data[0] >> 4 == 0x1:
            length = ((first_frame.data[0] & 0x0F) << 8) + first_frame.data[1]
            data = first_frame.data[2:]
            
            flow_control_data = bytearray([0x30, 0x00, 0x0A])
            
            if not is_fd:
                while len(flow_control_data) < 8:
                    flow_control_data.append(0x00)
            
            flow_control_message = can.Message(
                arbitration_id=arb_id, 
                data=flow_control_data, 
                is_extended_id=False,
                is_fd=is_fd
            )
            bus.send(flow_control_message)

            while len(data) < length:
                consecutive_frame = bus.recv(timeout=1.0)
                if consecutive_frame is None or consecutive_frame.arbitration_id not in expected_response_ids or consecutive_frame.data[0] >> 4 != 0x2:
                    print("未接收到连续帧")
                    return
                data += consecutive_frame.data[1:]

            return data[:length]

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

def extended_session(bus, arb_id, expected_response_ids, is_extend_id):
    print("🔄 进入扩展会话...")
    send_iso_tp_message(bus, arb_id, expected_response_ids, [0x10, 0x03], is_extend_id)
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    if response and response[0] == 0x50 and response[1] == 0x03:
        print("✅ 成功进入扩展会话")
        return True
    else:
        print("❌ 进入扩展会话失败")
        return False

def process_seed(bus, arb_id, data, level, expected_response_ids, is_extend_id, seed_data):
    inverted_data = [~b & 0xFF for b in seed_data]
    data_hex = ' '.join(f"{b:02X}" for b in inverted_data)
    print(f"🔄 处理种子数据 (取反): {data_hex}")
    sid_byte = 0x27
    subfunc_byte = level + 1
    can_data = bytearray([sid_byte, subfunc_byte] + inverted_data)

    send_iso_tp_message(bus, arb_id, expected_response_ids, can_data, is_extend_id)
    time.sleep(0.1)
    
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    if not response:
        print("❌ 发送密钥后无响应")
        return False

    if response[0] == 0x67 and response[1] == subfunc_byte:
        print("✅ ECU接受密钥")
        return True
    elif response[0] == 0x7F and response[2] != 0x36:
        switch_NRC(response[2])
        return False
    elif response[2] == 0x36:
        send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
        time.sleep(0.2)
        response1 = receive_iso_tp_message(bus, arb_id, expected_response_ids)
        if response1 is not None and response1[0] == 0x51:
            print("🔄 收到 ECU 重置")
            return None
        time.sleep(0.2)
        return None
    else:
        print(f"❌ 发送密钥后收到意外响应: {' '.join(f'{b:02X}' for b in response)}")
        return False

def auto_seed_key_attack(bus, arb_id, expected_response_ids, level, is_extend_id):
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
        print(f"\n{'='*30}")
        print(f"🔹 尝试算法: {alg_name}")
        print(f"{'='*30}")

        extended_session(bus, arb_id, expected_response_ids, is_extend_id)
        time.sleep(0.1)

        seed = request_seed(bus, arb_id, expected_response_ids, level, is_extend_id, choice=1)
        if not seed:
            print(f"❌ [{alg_name}] 未收到种子，跳过此算法")
            i += 1
            continue

        try:
            key_data = alg_func(seed)
        except Exception as e:
            print(f"⚠️ [{alg_name}] 算法错误: {e}")
            i += 1
            continue

        if not key_data or not isinstance(key_data, list):
            print(f"⚠️ [{alg_name}] 密钥生成结果无效")
            i += 1
            continue

        print(f"🔑 生成密钥 ({alg_name}): {' '.join(f'{b:02X}' for b in key_data)}")

        sid = 0x27
        subfunc = level + 1
        can_data = bytearray([sid, subfunc] + key_data)

        send_iso_tp_message(bus, arb_id, expected_response_ids, can_data, is_extend_id)
        time.sleep(0.15)

        response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
        if not response:
            print(f"❌ [{alg_name}] 发送密钥后无响应")
            i += 1
            continue

        if len(response) < 2:
            print(f"⚠️ [{alg_name}] 响应长度无效")
            i += 1
            continue

        if response[0] == 0x67 and response[1] == subfunc:
            print(f"🎉 [{alg_name}] 成功！ECU接受密钥")
            return True

        elif response[0] == 0x7F:
            if len(response) >= 3:
                nrc = response[2]
                switch_NRC(nrc)
                if nrc == 0x36:
                    print(f"🔁 [{alg_name}] 尝试次数过多，ECU需要重置")
                    send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
                    time.sleep(2.0)
                    response1 = receive_iso_tp_message(bus, arb_id, expected_response_ids)
                    if response1 is not None and response1[0] == 0x51:
                        print("🔄 收到 ECU 重置")
                        continue
                    else:
                        i += 1
                else:
                    i += 1
            else:
                print(f"⚠️ [{alg_name}] NRC响应格式错误")
                i += 1

        elif response[0] == 0x51:
            print(f"⚙️ [{alg_name}] ECU重置响应，跳过本轮")
            time.sleep(0.5)
            i += 1

        else:
            print(f"❌ [{alg_name}] 意外响应")
            i += 1

    print("\n❌ 所有算法均已尝试，未找到正确算法")
    return False

def send_key_random(bus, arb_id, seed, level, expected_response_ids, is_extend_id):
    if not seed:
        print("❌ 无种子数据，跳过密钥生成")
        return False

    sid_byte = 0x27
    subfunc_byte = level + 1
    key_data = [random.randint(0, 255) for _ in range(len(seed))]
    can_data = bytearray([sid_byte, subfunc_byte] + key_data)

    send_iso_tp_message(bus, arb_id, expected_response_ids, can_data, is_extend_id)
    time.sleep(0.1)

    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    if not response:
        print("❌ 发送密钥后无响应")
        return False

    if response[0] == 0x67 and response[1] == subfunc_byte:
        print("✅ ECU接受密钥")
        return True
    elif response[0] == 0x7F and response[2] != 0x36:
        switch_NRC(response[2])
        return False
    elif response[2] == 0x36:
        send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
        time.sleep(0.2)
        response1 = receive_iso_tp_message(bus, arb_id, expected_response_ids)
        if response1 is not None and response1[0] == 0x51:
            print("🔄 收到 ECU 重置")
            return None
        time.sleep(0.2)
        return None
    else:
        print(f"❌ 发送密钥后收到意外响应: {' '.join(f'{b:02X}' for b in response)}")
        return False

def request_seed(bus, arb_id, expected_response_ids, level, is_extend_id, choice):
    print(f"🔄 请求种子 (安全级别: 0x{level:02X})")
    request_data = [0x27, level]
    try:
        send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    except Exception as e:
        print(f"❌ 发送种子请求失败: {e}")
        return None
       
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response:
        print("❌ 未收到种子响应")
        return None

    response_data = " ".join("{:02X}".format(byte) for byte in response)
 
    if response[0] == 0x67 and response[1] == level:
        seed = response[2:]
        print(f"🔑 种子:", " ".join(format(b, '02X') for b in seed))
        Save_log(seed)
        return seed

    elif response[0] == 0x7F and response[2] != 0x36:
        print(f"❌ 请求失败. 响应数据:", response_data)
        switch_NRC(response[2])
        return None
    elif response[2] == 0x36:
        send_iso_tp_message(bus, arb_id, expected_response_ids, [0x11, 0x01], is_extend_id)
        time.sleep(0.2)
        return None
    else:
        print(f"❌ 意外响应:", response_data)

def read_memory(bus, start_address):
    is_fd = hasattr(bus, '_can_protocol') and bus._can_protocol == can.CanProtocol.CAN_FD

    print(f"💾 读取内存地址: 0x{start_address:08X}")
    msg = can.Message(
        arbitration_id=0x7E0, 
        data=[
            0x07, 0x23, 0x14,
            (start_address >> 24) & 0xFF,
            (start_address >> 16) & 0xFF,
            (start_address >> 8) & 0xFF,
            start_address & 0xFF,
            0xFF
        ], 
        is_extended_id=False,
        is_fd=is_fd,
        bitrate_switch=is_fd
    )
    bus.send(msg)

    all_data = []
    
    while True:
        response = bus.recv()
        if response:
            data = response.data
            all_data.extend(data)

            with open("hex_data.txt", "a") as hex_file:
                hex_file.write(' '.join(f"{b:02X}" for b in data) + '\n')

            if len(data) < len(response.data):
                break

    ascii_string = ''.join(chr(b) for b in all_data if 32 <= b <= 126)
    print(f"📍 地址: {hex(start_address)}, ASCII: {ascii_string}")

def read_data_by_identifier(bus, arb_id, expected_response_ids, did, is_extend_id):
    print(f"🔄 读取DID 0x{did:04X}")
    request_data = [0x22, (did >> 8) & 0xFF, did & 0xFF]
    
    send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)

    if not response:
        return None
    
    print(f"📥 DID 0x{did:04X} 响应:", " ".join(format(b, '02X') for b in response))
    
    if len(response) >= 3 and response[0] == 0x62:
        response_did = (response[1] << 8) | response[2]
        if response_did == did:
            data = response[3:]
            return list(data)
        else:
            print(f"❌ DID不匹配: 请求0x{did:04X}, 响应0x{response_did:04X}")
            return list(response)
    elif len(response) >= 3 and response[0] == 0x7F and response[1] == 0x22:
        nrc = response[2]
        return nrc
    
    print(f"❌ 未知响应格式: {' '.join(format(b, '02X') for b in response)}")
    return list(response)

def write_data_by_identifier(bus, arb_id, expected_response_ids, did, data, is_extend_id):
    print(f"📤 写入DID 0x{did:04X}")
    request_data = [0x2E, (did >> 8) & 0xFF, did & 0xFF] + data
    
    send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response:
        return None
        
    if len(response) >= 3 and response[0] == 0x6E:
        response_did = (response[1] << 8) | response[2]
        if response_did == did:
            return True
    elif len(response) >= 3 and response[0] == 0x7F and response[1] == 0x2E:
        nrc = response[2]
        return nrc
    
    return None

def scan_all_dids_mode0(bus, arb_id, expected_response_ids, is_extend_id, start_did=0x0000, end_did=0xFFFF):
    print(f"🔍 开始扫描 DID 范围: 0x{start_did:04X} 到 0x{end_did:04X}")
    print("="*80)
    print(f"{'DID':<8} {'HEX数据':<30} {'ASCII表示':<20} {'状态'}")
    print("-"*80)
    
    found_dids = []
    
    for did in range(start_did, end_did + 1):
        try:
            result = read_data_by_identifier(bus, arb_id, expected_response_ids, did, is_extend_id)
            
            if result is None:
                pass
            elif isinstance(result, list):
                hex_data = ' '.join(f"{b:02X}" for b in result)
                ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result)
                print(f"0x{did:04X}   {hex_data:<30} {ascii_data:<20} 成功")
                found_dids.append((did, result, "success"))
            elif isinstance(result, int):
                print(f"0x{did:04X}   {'NRC: 0x{:02X}'.format(result):<30} {'':<20} ", end="")
                switch_NRC(result)
                found_dids.append((did, None, f"NRC: 0x{result:02X}"))
            
            if did % 100 == 0 and did != 0:
                print(f"📊 进度: {did}/{end_did} (0x{did:04X}/0x{end_did:04X})")
                
            time.sleep(0.01)
            
        except Exception as e:
            print(f"❌ DID 0x{did:04X}: 错误 - {e}")
            found_dids.append((did, None, f"Error: {e}"))
            continue
    
    print("="*80)
    success_count = len([d for d in found_dids if d[2] == "success"])
    nrc_count = len([d for d in found_dids if d[2].startswith("NRC")])
    error_count = len([d for d in found_dids if d[2].startswith("Error")])
    
    print(f"✅ 扫描完成，共发现 {len(found_dids)} 个响应DID:")
    print(f"  - 成功读取: {success_count}")
    print(f"  - 负响应: {nrc_count}")
    print(f"  - 错误: {error_count}")
    
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
    
    print(f"\n📄 详细结果已保存到 did_scan_results.txt")
    return found_dids

def test_write_did_mode1(bus, arb_id, expected_response_ids, is_extend_id, start_did=0x0000, end_did=0xFFFF):
    print(f"📝 开始测试 DID 写入服务，范围: 0x{start_did:04X} 到 0x{end_did:04X}")
    print("="*60)
    print(f"{'DID':<8} {'响应'}")
    print("-"*60)
    
    results = []
    test_data = [0x01, 0x02, 0x03, 0x04]
    
    for did in range(start_did, end_did + 1):
        try:
            result = write_data_by_identifier(bus, arb_id, expected_response_ids, did, test_data, is_extend_id)
            
            if result is None:
                print(f"0x{did:04X}   无响应")
                results.append((did, "无响应"))
            elif result is True:
                print(f"0x{did:04X}   写入成功")
                results.append((did, "写入成功"))
            elif isinstance(result, int):
                print(f"0x{did:04X}   ", end="")
                switch_NRC(result)
                results.append((did, f"NRC: 0x{result:02X}"))
            
            if did % 50 == 0 and did != 0:
                print(f"📊 进度: {did}/{end_did} (0x{did:04X}/0x{end_did:04X})")
                
            time.sleep(0.02)
            
        except Exception as e:
            print(f"❌ DID 0x{did:04X}: 错误 - {e}")
            results.append((did, f"错误: {e}"))
            continue
    
    with open("write_did_test_results.txt", "w", encoding="utf-8") as f:
        f.write(f"DID写入测试结果\n")
        f.write(f"{'DID':<8} {'响应'}\n")
        f.write("-"*60 + "\n")
        
        for did, response in results:
            f.write(f"0x{did:04X}   {response}\n")
    
    print("="*60)
    print(f"✅ 测试完成，结果已保存到 write_did_test_results.txt")
    return results

def get_did_scan_range():
    print("🔧 请输入要扫描的DID范围:")
    start_input = input("起始 DID (hex, 默认 0000): ").strip()
    end_input = input("结束 DID (hex, 默认 FFFF): ").strip()
    
    try:
        start_did = int(start_input, 16) if start_input else 0x0000
        end_did = int(end_input, 16) if end_input else 0xFFFF
        
        if start_did > end_did:
            print("❌ 起始DID不能大于结束DID，使用默认范围")
            return 0x0000, 0xFFFF
            
        return start_did, end_did
    except ValueError:
        print("❌ 输入格式错误，使用默认范围 0x0000-0xFFFF")
        return 0x0000, 0xFFFF

def get_scan_mode():
    mode_input = input("请选择模式 (0: 读取DID并显示数据, 1: 发送写入DID请求并返回NRC, 默认 0): ").strip()
    try:
        mode = int(mode_input) if mode_input else 0
        if mode not in [0, 1]:
            print("❌ 模式必须是0或1，使用默认模式0")
            return 0
        return mode
    except ValueError:
        print("❌ 输入格式错误，使用默认模式0")
        return 0

def print_log_header():
    print("   .               .    ")
    print(" .´  ·  .     .  ·  `.  UDS TEST")
    print(" :  :  :  (¯)  :  :  :  A CAN Test Tool")
    print(" `.  ·  ` /¯\\ ´  ·  .´  by 1in-oos")
    print("   `     /¯¯¯\\     ´   https://github.com/1in-oos/seedtest.git")
    print("="*50)

def get_arbitration_id():
    id_input = input("🔧 输入CAN消息ID (hex, 留空使用默认 7E0): ").strip()
    if id_input:
        return int(id_input, 16)
    else:
        return 0x7E0

def get_response_ids(arb_id):
    """获取响应ID列表"""
    print("🔧 输入响应ID (多个ID用空格分隔，留空使用默认规则):")
    response_input = input("响应ID (hex): ").strip()
    
    if response_input:
        try:
            response_ids = {int(id_str, 16) for id_str in response_input.split()}
            return response_ids
        except ValueError:
            print("❌ 输入格式错误，使用默认规则")
    
    # 默认规则
    return {arb_id + 8, arb_id - 8, (arb_id & 0xFFFF0000) | ((arb_id & 0x0000FF00) >> 8) | ((arb_id & 0x000000FF) << 8)}

def UDS_SID():
    SID = input("🔧 输入服务标识符 (hex, 留空使用默认 27): ").strip()
    if SID:
        return int(SID, 16)
    else:
        return 0x27
    
def get_27_level():
    level_input = input("🔧 输入27安全访问级别 (hex, 留空使用默认 01): ").strip()
    if level_input:
        seed_choice = get_seed_choice()
        return int(level_input, 16), seed_choice
    else:
        seed_choice = get_seed_choice()
        return 0x01, seed_choice

def get_seed_choice():
    print("\n🔧 选择种子爆破模式:")
    print("  0: 不进行爆破")
    print("  1: 随机密钥爆破")
    print("  2: 取反算法")
    print("  3: 多算法爆破")
    choice_input = input("请选择 (0-3, 默认 0): ").strip()
    if choice_input:
        return int(choice_input)
    else:
        return 0

def get_can_mode():
    mode_input = input("🔧 选择CAN模式 (0: Classic CAN, 1: CAN FD, 默认 0): ").strip()
    try:
        mode = int(mode_input) if mode_input else 0
        if mode not in [0, 1]:
            print("❌ 模式必须是0或1，使用默认模式0 (Classic CAN)")
            return False
        return bool(mode)
    except ValueError:
        print("❌ 输入格式错误，使用默认模式0 (Classic CAN)")
        return False

def send_custom_diagnostic_data(bus, arb_id, expected_response_ids, is_extend_id):
    """发送自定义诊断数据"""
    print("\n🎮 发送自定义诊断数据")
    print("输入十六进制数据 (如: 10 03, 22 F1 90)")
    print("输入 'q' 或 'quit' 返回主菜单")
    print("-" * 50)
    
    while True:
        try:
            cmd = input("\n🔧 诊断数据> ").strip().lower()
            
            if cmd in ['q', 'quit', 'exit']:
                print("👋 返回主菜单")
                break
                
            if not cmd:
                continue
                
            # 解析十六进制数据
            try:
                hex_bytes = [int(b, 16) for b in cmd.split()]
                print(f"📤 发送: {' '.join(f'{b:02X}' for b in hex_bytes)}")
                
                # 发送数据
                send_iso_tp_message(bus, arb_id, expected_response_ids, hex_bytes, is_extend_id)
                
                # 接收响应
                response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
                if response:
                    print(f"📥 响应: {' '.join(f'{b:02X}' for b in response)}")
                    
                    # 特殊响应处理
                    if len(response) >= 2 and response[0] == 0x7F:
                        if len(response) >= 3:
                            switch_NRC(response[2])
                else:
                    print("❌ 无响应")
                    
            except ValueError:
                print("❌ 无效的十六进制格式")
            except Exception as e:
                print(f"❌ 发送数据失败: {e}")
                
        except KeyboardInterrupt:
            print("\n👋 收到中断信号，返回主菜单...")
            break
        except EOFError:
            print("\n👋 输入结束，返回主菜单...")
            break

def main():
    print_log_header()
    arb_id = get_arbitration_id()
    response_ids = get_response_ids(arb_id)
    SID = UDS_SID()
    start_address = 0xC3F80000
    is_extend_id = arb_id > 0x7FF
    
    use_fd = get_can_mode()
    
    filters = []
    for resp_id in response_ids:
        filters.append({
            "can_id": resp_id,
            "can_mask": 0x1FFFFFFF if resp_id > 0x7FF else 0x7FF,
            "extended": resp_id > 0x7FF
        })
    
    # 添加请求ID过滤器
    filters.append({
        "can_id": arb_id,
        "can_mask": 0x1FFFFFFF if arb_id > 0x7FF else 0x7FF,
        "extended": arb_id > 0x7FF
    })

    try:
        if use_fd:
            bus = can.interface.Bus(
                channel="can0", 
                interface="socketcan", 
                can_filters=filters,
                fd=True
            )
            print("✅ 使用 CAN FD 模式")
        else:
            bus = can.interface.Bus(
                channel="can0", 
                interface="socketcan", 
                can_filters=filters
            )
            print("✅ 使用 Classic CAN 模式")
    except Exception as e:
        print(f"❌ 初始化CAN总线失败: {e}")
        return

    signal.signal(signal.SIGINT, signal_handler)

    if SID == 0x27:
        level, seed_choice = get_27_level()

        print("\n📋 配置摘要:")
        print(f"  CAN ID: {hex(arb_id)}")
        print(f"  响应ID: {[hex(id) for id in response_ids]}")
        print(f"  安全访问级别: {hex(level)}")
        print(f"  爆破模式: {seed_choice}")
        
        try:
            if seed_choice == 0:
                print("🔄 请求种子 1000 次")
                for i in range(1000):
                    print(f"📍 第 {i+1} 次请求")
                    extended_session(bus, arb_id, response_ids, is_extend_id)
                    time.sleep(0.01)
                    request_seed(bus, arb_id, response_ids, level, is_extend_id, seed_choice)
                    time.sleep(0.01)
                    
            elif seed_choice == 1:
                print("🎲 请求种子并进行随机密钥爆破")
                success = False
                for i in range(10):
                    print(f"📍 第 {i+1} 次尝试")
                    extended_session(bus, arb_id, response_ids, is_extend_id)
                    time.sleep(0.1)
                    seed = request_seed(bus, arb_id, response_ids, level, is_extend_id, seed_choice)
                    time.sleep(0.1)
                    if seed is None:
                        print("⚠️ 未收到种子，跳过密钥尝试")
                        time.sleep(0.5)
                        continue
                    result = send_key_random(bus, arb_id, seed, level, response_ids, is_extend_id)
                    if result is True:
                        print("🎉 安全访问成功!")
                        success = True
                        break
                    elif result is None:
                        print("⏳ ECU需要延迟，等待...")
                        time.sleep(2)
                        continue
                    else:
                        print("🔑 密钥被拒绝，继续尝试...")
                        time.sleep(0.5)
                
            elif seed_choice == 2:
                print("🔄 请求种子并使用取反算法")
                extended_session(bus, arb_id, response_ids, is_extend_id)
                time.sleep(0.1)
                seed = request_seed(bus, arb_id, response_ids, level, is_extend_id, seed_choice)
                process_seed(bus, arb_id, seed, level, response_ids, is_extend_id, seed)
                
            elif seed_choice == 3:
                print("🧠 请求种子并进行多算法爆破")
                auto_seed_key_attack(bus, arb_id, response_ids, level, is_extend_id)
                   
        except KeyboardInterrupt:
            bus.shutdown()
            print("\n👋 Ctrl+C detected. Exiting...")
        finally:
            bus.shutdown()
            
    elif SID == 0x23:
        try:
            read_memory(bus, start_address)
            start_address += 0xFF
            time.sleep(0.1)

        except KeyboardInterrupt:
            bus.shutdown()
            print("\n👋 Ctrl+C detected. Exiting...")
        finally:
            bus.shutdown()
            
    elif SID == 0x22:
        print("🔍 执行 ReadDataByIdentifier (0x22) DID 扫描")
        mode = get_scan_mode()
        extended_session(bus, arb_id, response_ids, is_extend_id)
        time.sleep(0.01)
        start_did, end_did = get_did_scan_range()
        
        try:
            if mode == 0:
                print("📊 模式0: 遍历DID并显示数据")
                scan_all_dids_mode0(bus, arb_id, response_ids, is_extend_id, start_did, end_did)
            elif mode == 1:
                print("📝 模式1: 发送写入DID请求并返回NRC")
                test_write_did_mode1(bus, arb_id, response_ids, is_extend_id, start_did, end_did)
                
        except KeyboardInterrupt:
            print("\n👋 用户中断操作...")
        finally:
            bus.shutdown()
            
    else:
        # 进入交互模式
        print("🎮 进入交互诊断模式")
        extended_session(bus, arb_id, response_ids, is_extend_id)
        interactive_mode(bus, arb_id, response_ids, is_extend_id)
        bus.shutdown()

if __name__ == "__main__":
    main()