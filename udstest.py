# udstest.py - UDS诊断测试工具（优化版）
"""
UDS (Unified Diagnostic Services) 测试工具
支持通过CAN总线进行ECU诊断、安全访问、DID扫描等功能
"""
import can
import time
import signal
import sys
import random
import threading
from typing import Optional, List, Tuple, Set, Dict, Callable
from enum import IntEnum

# ==================== 常量定义 ====================
class UDSServiceID:
    """UDS服务ID常量"""
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    READ_DATA_BY_IDENTIFIER = 0x22
    READ_MEMORY_BY_ADDRESS = 0x23
    SECURITY_ACCESS = 0x27
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    TESTER_PRESENT = 0x3E

class SessionType:
    """诊断会话类型"""
    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED = 0x03

class ResponseCode:
    """响应码"""
    POSITIVE_RESPONSE_OFFSET = 0x40
    NEGATIVE_RESPONSE = 0x7F

class NRC:
    """负响应码"""
    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_MESSAGE_LENGTH = 0x13
    RESPONSE_TOO_LONG = 0x14
    BUSY_REPEAT_REQUEST = 0x21
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    REQUEST_OUT_OF_RANGE = 0x25
    SECURITY_ACCESS_DENIED = 0x26
    INVALID_KEY = 0x35
    EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
    REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING = 0x78
    SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E

# ISO-TP 常量
ISO_TP_SINGLE_FRAME = 0x0
ISO_TP_FIRST_FRAME = 0x1
ISO_TP_CONSECUTIVE_FRAME = 0x2
ISO_TP_FLOW_CONTROL = 0x3

# CAN 常量
CAN_STD_ID_MAX = 0x7FF
CAN_EXT_ID_MASK = 0x1FFFFFFF
CAN_STD_ID_MASK = 0x7FF

# 默认值
DEFAULT_ARB_ID = 0x7E0
DEFAULT_SID = 0x27
DEFAULT_SECURITY_LEVEL = 0x01
DEFAULT_CHANNEL = "can0"
DEFAULT_INTERFACE = "socketcan"
DEFAULT_TIMEOUT = 1.0
SESSION_KEEP_ALIVE_INTERVAL = 5.0

# 帧大小
CAN_CLASSIC_MAX_DATA = 8
CAN_CLASSIC_SF_MAX = 7
CAN_CLASSIC_FF_MAX = 6
CAN_CLASSIC_CF_MAX = 7
CAN_FD_MAX_DATA = 64
CAN_FD_SF_MAX = 62
CAN_FD_FF_MAX = 62
CAN_FD_CF_MAX = 63

# ==================== 全局变量 ====================
keep_session_alive: bool = False
alive_check_thread: Optional[threading.Thread] = None

# ==================== NRC错误码映射 ====================
NRC_DESCRIPTIONS: Dict[int, str] = {
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

# ==================== 工具函数 ====================
def print_nrc(nrc_code: int) -> None:
    """打印NRC错误码描述"""
    description = NRC_DESCRIPTIONS.get(nrc_code, f"未知 NRC: {nrc_code:02X}")
    print(f"NRC=={nrc_code:02X}, {description}")

def format_hex_data(data: List[int]) -> str:
    """格式化十六进制数据为字符串"""
    return ' '.join(f'{b:02X}' for b in data)

def is_can_fd(bus) -> bool:
    """检查总线是否支持CAN FD"""
    return hasattr(bus, '_can_protocol') and bus._can_protocol == can.CanProtocol.CAN_FD

def get_can_frame_sizes(bus) -> Tuple[int, int, int]:
    """获取CAN帧大小限制"""
    if is_can_fd(bus):
        return CAN_FD_SF_MAX, CAN_FD_FF_MAX, CAN_FD_CF_MAX
    else:
        return CAN_CLASSIC_SF_MAX, CAN_CLASSIC_FF_MAX, CAN_CLASSIC_CF_MAX

def create_can_filter(can_id: int) -> Dict:
    """创建CAN过滤器"""
    return {
        "can_id": can_id,
        "can_mask": CAN_EXT_ID_MASK if can_id > CAN_STD_ID_MAX else CAN_STD_ID_MASK,
        "extended": can_id > CAN_STD_ID_MAX
    }

# ==================== ISO-TP 消息处理 ====================
def send_iso_tp_message(
    bus, 
    arb_id: int, 
    expected_response_ids: Set[int], 
    data: List[int], 
    is_extend_id: bool
) -> bool:
    """
    发送 ISO-TP 消息，支持CAN和CAN FD
    
    Args:
        bus: CAN总线对象
        arb_id: 仲裁ID
        expected_response_ids: 期望的响应ID集合
        data: 要发送的数据
        is_extend_id: 是否使用扩展ID
        
    Returns:
        bool: 发送是否成功
    """
    try:
        sf_max, ff_max, cf_max = get_can_frame_sizes(bus)
        is_fd = is_can_fd(bus)
        
        if len(data) <= sf_max:
            # 单帧传输
            can_data = bytearray([len(data)] + list(data))
            if not is_fd:
                can_data.extend([0x00] * (CAN_CLASSIC_MAX_DATA - len(can_data)))
            
            message = can.Message(
                arbitration_id=arb_id,
                data=can_data,
                is_extended_id=is_extend_id,
                is_fd=is_fd,
                bitrate_switch=is_fd
            )
            bus.send(message)
            return True
        else:
            # 多帧传输 - 首帧
            ff_data = data[:ff_max]
            can_data = bytearray([(ISO_TP_FIRST_FRAME << 4) | (len(data) >> 8), len(data) & 0xFF] + list(ff_data))
            
            if not is_fd:
                while len(can_data) < CAN_CLASSIC_MAX_DATA:
                    can_data.append(0x00)
            
            message = can.Message(
                arbitration_id=arb_id,
                data=can_data,
                is_extended_id=is_extend_id,
                is_fd=False  # 首帧不使用FD
            )
            bus.send(message)
            
            # 等待流控帧
            flow_control_message = bus.recv(timeout=DEFAULT_TIMEOUT)
            if (flow_control_message is None or 
                flow_control_message.arbitration_id not in expected_response_ids or
                (flow_control_message.data[0] >> 4) != ISO_TP_FLOW_CONTROL):
                print("⚠️ 流控帧接收失败")
                return False
            
            block_size = flow_control_message.data[1]
            st_min = flow_control_message.data[2]
            
            # 发送连续帧
            remaining_data = data[ff_max:]
            frame_id = 1
            
            while remaining_data:
                cf_data = remaining_data[:cf_max]
                remaining_data = remaining_data[cf_max:]
                can_data = bytearray([(ISO_TP_CONSECUTIVE_FRAME << 4) | frame_id] + list(cf_data))
                
                if not is_fd:
                    while len(can_data) < CAN_CLASSIC_MAX_DATA:
                        can_data.append(0x55)
                
                message = can.Message(
                    arbitration_id=arb_id,
                    data=can_data,
                    is_extended_id=is_extend_id,
                    is_fd=False
                )
                bus.send(message)
                frame_id = (frame_id + 1) % 16
                
                if st_min > 0:
                    time.sleep(st_min / 1000.0)
            
            return True
    except Exception as e:
        print(f"❌ 发送ISO-TP消息失败: {e}")
        return False

def receive_iso_tp_message(
    bus, 
    arb_id: int, 
    expected_response_ids: Set[int],
    timeout: float = DEFAULT_TIMEOUT,
    max_retries: int = 3
) -> Optional[List[int]]:
    """
    接收 ISO-TP 消息，支持CAN和CAN FD
    
    Args:
        bus: CAN总线对象
        arb_id: 仲裁ID
        expected_response_ids: 期望的响应ID集合
        timeout: 超时时间（秒）
        max_retries: 最大重试次数
        
    Returns:
        Optional[List[int]]: 接收到的数据，失败返回None
    """
    for retry in range(max_retries):
        try:
            first_frame = bus.recv(timeout=timeout)
            if first_frame is None:
                if retry < max_retries - 1:
                    continue
                print("⚠️ 未接收到首帧")
                return None
            
            if first_frame.arbitration_id not in expected_response_ids:
                if retry < max_retries - 1:
                    continue
                print(f"⚠️ 收到非期望ID: 0x{first_frame.arbitration_id:X}")
                return None
            
            is_fd = getattr(first_frame, 'is_fd', False)
            pci = first_frame.data[0] >> 4
            
            if pci == ISO_TP_SINGLE_FRAME:
                # 单帧
                length = first_frame.data[0] & 0x0F
                if length == 0:
                    return []
                data = list(first_frame.data[1:length+1])
                return data
                
            elif pci == ISO_TP_FIRST_FRAME:
                # 首帧
                length = ((first_frame.data[0] & 0x0F) << 8) + first_frame.data[1]
                data = list(first_frame.data[2:])
                
                # 发送流控帧
                flow_control_data = bytearray([(ISO_TP_FLOW_CONTROL << 4) | 0x0, 0x00, 0x0A])
                if not is_fd:
                    while len(flow_control_data) < CAN_CLASSIC_MAX_DATA:
                        flow_control_data.append(0x00)
                
                flow_control_message = can.Message(
                    arbitration_id=arb_id,
                    data=flow_control_data,
                    is_extended_id=False,
                    is_fd=is_fd
                )
                bus.send(flow_control_message)
                
                # 接收连续帧
                frame_id = 1
                while len(data) < length:
                    consecutive_frame = bus.recv(timeout=timeout)
                    if (consecutive_frame is None or 
                        consecutive_frame.arbitration_id not in expected_response_ids):
                        print("⚠️ 未接收到连续帧")
                        return None
                    
                    pci = consecutive_frame.data[0] >> 4
                    if pci != ISO_TP_CONSECUTIVE_FRAME:
                        print(f"⚠️ 收到非连续帧: {pci:X}")
                        return None
                    
                    expected_frame_id = frame_id % 16
                    received_frame_id = consecutive_frame.data[0] & 0x0F
                    if received_frame_id != expected_frame_id:
                        print(f"⚠️ 帧序号错误: 期望{expected_frame_id}, 收到{received_frame_id}")
                        return None
                    
                    data.extend(list(consecutive_frame.data[1:]))
                    frame_id += 1
                
                return data[:length]
            else:
                print(f"⚠️ 收到未知PCI类型: {pci:X}")
                if retry < max_retries - 1:
                    continue
                return None
                
        except Exception as e:
            print(f"⚠️ 接收ISO-TP消息出错: {e}")
            if retry < max_retries - 1:
                continue
            return None
    
    return None

# ==================== 会话管理 ====================
def extended_session(
    bus, 
    arb_id: int, 
    expected_response_ids: Set[int], 
    is_extend_id: bool
) -> bool:
    """
    进入扩展会话
    
    Returns:
        bool: 是否成功进入扩展会话
    """
    print("🔄 进入扩展会话...")
    send_iso_tp_message(
        bus, arb_id, expected_response_ids, 
        [UDSServiceID.DIAGNOSTIC_SESSION_CONTROL, SessionType.EXTENDED], 
        is_extend_id
    )
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if response and len(response) >= 2:
        if (response[0] == (UDSServiceID.DIAGNOSTIC_SESSION_CONTROL + ResponseCode.POSITIVE_RESPONSE_OFFSET) and 
            response[1] == SessionType.EXTENDED):
            print("✅ 成功进入扩展会话")
            return True
    
    print("❌ 进入扩展会话失败")
    if response:
        print(f"   响应: {format_hex_data(response)}")
    return False

def switch_session(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    is_extend_id: bool,
    session_type: int
) -> bool:
    """
    切换诊断会话
    
    Args:
        session_type: 会话类型
        
    Returns:
        bool: 是否成功切换
    """
    print(f"🔄 切换到诊断会话 0x{session_type:02X}")
    send_iso_tp_message(
        bus, arb_id, expected_response_ids,
        [UDSServiceID.DIAGNOSTIC_SESSION_CONTROL, session_type],
        is_extend_id
    )
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if response and len(response) >= 2:
        expected_response = UDSServiceID.DIAGNOSTIC_SESSION_CONTROL + ResponseCode.POSITIVE_RESPONSE_OFFSET
        if response[0] == expected_response and response[1] == session_type:
            print(f"✅ 成功切换到会话 0x{session_type:02X}")
            return True
    
    print(f"❌ 切换会话失败")
    if response:
        print(f"   响应: {format_hex_data(response)}")
        if len(response) >= 3 and response[0] == ResponseCode.NEGATIVE_RESPONSE:
            print_nrc(response[2])
    return False

# ==================== 会话保持 ====================
def session_keep_alive(
    bus, 
    arb_id: int, 
    expected_response_ids: Set[int], 
    is_extend_id: bool
) -> None:
    """会话保持线程函数"""
    global keep_session_alive
    while keep_session_alive:
        try:
            send_iso_tp_message(
                bus, arb_id, expected_response_ids,
                [UDSServiceID.TESTER_PRESENT, 0x00],
                is_extend_id
            )
            receive_iso_tp_message(bus, arb_id, expected_response_ids, timeout=0.5)
            time.sleep(SESSION_KEEP_ALIVE_INTERVAL)
        except Exception as e:
            if keep_session_alive:
                print(f"⚠️ 会话保持出错: {e}")
            break

def start_session_keep_alive(
    bus, 
    arb_id: int, 
    expected_response_ids: Set[int], 
    is_extend_id: bool
) -> None:
    """启动会话保持"""
    global keep_session_alive, alive_check_thread
    if not keep_session_alive:
        keep_session_alive = True
        alive_check_thread = threading.Thread(
            target=session_keep_alive,
            args=(bus, arb_id, expected_response_ids, is_extend_id),
            daemon=True
        )
        alive_check_thread.start()
        print("✅ 会话保持已启动")

def stop_session_keep_alive() -> None:
    """停止会话保持"""
    global keep_session_alive, alive_check_thread
    if keep_session_alive:
        keep_session_alive = False
        if alive_check_thread and alive_check_thread.is_alive():
            alive_check_thread.join(timeout=1.0)
        print("⏹️ 会话保持已停止")

# ==================== 安全访问 ====================
def request_seed(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    level: int,
    is_extend_id: bool,
    choice: int = 0
) -> Optional[List[int]]:
    """
    请求安全访问种子
    
    Args:
        level: 安全访问级别
        choice: 选择模式（用于日志记录）
        
    Returns:
        Optional[List[int]]: 种子数据，失败返回None
    """
    print(f"🔄 请求种子 (安全级别: 0x{level:02X})")
    request_data = [UDSServiceID.SECURITY_ACCESS, level]
    
    try:
        if not send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id):
            return None
    except Exception as e:
        print(f"❌ 发送种子请求失败: {e}")
        return None
    
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response or len(response) < 2:
        print("❌ 未收到种子响应")
        return None
    
    expected_response = UDSServiceID.SECURITY_ACCESS + ResponseCode.POSITIVE_RESPONSE_OFFSET
    if response[0] == expected_response and response[1] == level:
        seed = response[2:]
        print(f"🔑 种子: {format_hex_data(seed)}")
        save_seed_log(seed)
        return seed
    
    elif response[0] == ResponseCode.NEGATIVE_RESPONSE:
        if len(response) >= 3:
            if response[1] == UDSServiceID.SECURITY_ACCESS:
                print(f"❌ 请求失败. 响应: {format_hex_data(response)}")
                print_nrc(response[2])
                
                if response[2] == NRC.EXCEEDED_NUMBER_OF_ATTEMPTS:
                    # 需要重置ECU
                    print("🔄 尝试次数过多，执行ECU重置...")
                    send_iso_tp_message(
                        bus, arb_id, expected_response_ids,
                        [UDSServiceID.ECU_RESET, 0x01],
                        is_extend_id
                    )
                    time.sleep(0.2)
                    receive_iso_tp_message(bus, arb_id, expected_response_ids, timeout=0.5)
        return None
    else:
        print(f"❌ 意外响应: {format_hex_data(response)}")
        return None

def send_key(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    level: int,
    key_data: List[int],
    is_extend_id: bool
) -> Optional[bool]:
    """
    发送安全访问密钥
    
    Args:
        level: 安全访问级别
        key_data: 密钥数据
        
    Returns:
        Optional[bool]: True=成功, False=失败, None=需要延迟或重置
    """
    subfunc = level + 1
    can_data = [UDSServiceID.SECURITY_ACCESS, subfunc] + key_data
    
    if not send_iso_tp_message(bus, arb_id, expected_response_ids, can_data, is_extend_id):
        return False
    
    time.sleep(0.1)
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response or len(response) < 2:
        print("❌ 发送密钥后无响应")
        return False
    
    expected_response = UDSServiceID.SECURITY_ACCESS + ResponseCode.POSITIVE_RESPONSE_OFFSET
    if response[0] == expected_response and response[1] == subfunc:
        print("✅ ECU接受密钥")
        return True
    
    elif response[0] == ResponseCode.NEGATIVE_RESPONSE and len(response) >= 3:
        if response[1] == UDSServiceID.SECURITY_ACCESS:
            nrc = response[2]
            print_nrc(nrc)
            
            if nrc == NRC.EXCEEDED_NUMBER_OF_ATTEMPTS:
                # 需要重置
                print("🔄 尝试次数过多，执行ECU重置...")
                send_iso_tp_message(
                    bus, arb_id, expected_response_ids,
                    [UDSServiceID.ECU_RESET, 0x01],
                    is_extend_id
                )
                time.sleep(0.2)
                reset_response = receive_iso_tp_message(bus, arb_id, expected_response_ids, timeout=0.5)
                if reset_response and len(reset_response) > 0 and reset_response[0] == 0x51:
                    print("🔄 收到ECU重置响应")
                return None
            elif nrc == NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED:
                return None
    
    print(f"❌ 发送密钥后收到意外响应: {format_hex_data(response)}")
    return False

def process_seed_invert(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    level: int,
    seed_data: List[int],
    is_extend_id: bool
) -> Optional[bool]:
    """
    使用取反算法处理种子
    
    Returns:
        Optional[bool]: 处理结果
    """
    if not seed_data:
        print("❌ 无种子数据")
        return False
    
    inverted_data = [~b & 0xFF for b in seed_data]
    print(f"🔄 处理种子数据 (取反): {format_hex_data(inverted_data)}")
    
    return send_key(bus, arb_id, expected_response_ids, level, inverted_data, is_extend_id)

def send_key_random(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    level: int,
    seed: List[int],
    is_extend_id: bool
) -> Optional[bool]:
    """
    发送随机密钥
    
    Returns:
        Optional[bool]: 处理结果
    """
    if not seed:
        print("❌ 无种子数据，跳过密钥生成")
        return False
    
    key_data = [random.randint(0, 255) for _ in range(len(seed))]
    print(f"🔑 生成随机密钥: {format_hex_data(key_data)}")
    
    return send_key(bus, arb_id, expected_response_ids, level, key_data, is_extend_id)

def auto_seed_key_attack(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    level: int,
    is_extend_id: bool
) -> bool:
    """
    多算法自动爆破攻击
    
    Returns:
        bool: 是否成功
    """
    algorithms: Dict[str, Callable[[List[int]], List[int]]] = {
        "xor_55": lambda s: [b ^ 0x55 for b in s],
        "xor_AA": lambda s: [b ^ 0xAA for b in s],
        "add_1": lambda s: [(b + 1) & 0xFF for b in s],
        "sub_1": lambda s: [(b - 1) & 0xFF for b in s],
        "add_index": lambda s: [(b + i) & 0xFF for i, b in enumerate(s)],
        "xor_index": lambda s: [b ^ i for i, b in enumerate(s)],
        "swap_pairs": lambda s: [s[i ^ 1] if (i ^ 1) < len(s) else s[i] for i in range(len(s))],
        "invert": lambda s: [~b & 0xFF for b in s],
    }
    
    for alg_name, alg_func in algorithms.items():
        print(f"\n{'='*30}")
        print(f"🔹 尝试算法: {alg_name}")
        print(f"{'='*30}")
        
        # 进入扩展会话
        if not extended_session(bus, arb_id, expected_response_ids, is_extend_id):
            print(f"❌ [{alg_name}] 无法进入扩展会话")
            continue
        
        time.sleep(0.1)
        
        # 请求种子
        seed = request_seed(bus, arb_id, expected_response_ids, level, is_extend_id, choice=1)
        if not seed:
            print(f"❌ [{alg_name}] 未收到种子，跳过此算法")
            continue
        
        # 生成密钥
        try:
            key_data = alg_func(seed)
        except Exception as e:
            print(f"⚠️ [{alg_name}] 算法错误: {e}")
            continue
        
        if not key_data or not isinstance(key_data, list):
            print(f"⚠️ [{alg_name}] 密钥生成结果无效")
            continue
        
        print(f"🔑 生成密钥 ({alg_name}): {format_hex_data(key_data)}")
        
        # 发送密钥
        result = send_key(bus, arb_id, expected_response_ids, level, key_data, is_extend_id)
        
        if result is True:
            print(f"🎉 [{alg_name}] 成功！ECU接受密钥")
            return True
        elif result is None:
            print(f"⏳ [{alg_name}] ECU需要延迟或重置，等待...")
            time.sleep(2.0)
            continue
        else:
            print(f"🔑 [{alg_name}] 密钥被拒绝，继续尝试...")
            time.sleep(0.5)
    
    print("\n❌ 所有算法均已尝试，未找到正确算法")
    return False

# ==================== 日志和工具函数 ====================
def save_seed_log(seed: List[int]) -> None:
    """保存种子日志"""
    log_file = "seed.log_hex"
    hex_seed = format_hex_data(seed)
    
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(hex_seed + '\n')
    except Exception as e:
        print(f"⚠️ 保存日志失败: {e}")

def signal_handler(sig, frame) -> None:
    """信号处理器"""
    print("\n⚠️ 收到中断信号，正在退出...")
    stop_session_keep_alive()
    sys.exit(0)

# ==================== DID操作 ====================
def read_data_by_identifier(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    did: int,
    is_extend_id: bool
) -> Optional[Tuple[List[int], Optional[int]]]:
    """
    读取数据标识符
    
    Returns:
        Optional[Tuple[List[int], Optional[int]]]: (数据, NRC) 或 None
    """
    print(f"🔄 读取DID 0x{did:04X}")
    request_data = [
        UDSServiceID.READ_DATA_BY_IDENTIFIER,
        (did >> 8) & 0xFF,
        did & 0xFF
    ]
    
    send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response:
        return None
    
    print(f"📥 DID 0x{did:04X} 响应: {format_hex_data(response)}")
    
    expected_response = UDSServiceID.READ_DATA_BY_IDENTIFIER + ResponseCode.POSITIVE_RESPONSE_OFFSET
    if len(response) >= 3 and response[0] == expected_response:
        response_did = (response[1] << 8) | response[2]
        if response_did == did:
            data = response[3:]
            return (data, None)
        else:
            print(f"❌ DID不匹配: 请求0x{did:04X}, 响应0x{response_did:04X}")
            return (response, None)
    
    elif len(response) >= 3 and response[0] == ResponseCode.NEGATIVE_RESPONSE:
        if response[1] == UDSServiceID.READ_DATA_BY_IDENTIFIER:
            nrc = response[2]
            return (None, nrc)
    
    print(f"❌ 未知响应格式: {format_hex_data(response)}")
    return (response, None)

def write_data_by_identifier(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    did: int,
    data: List[int],
    is_extend_id: bool
) -> Optional[Tuple[bool, Optional[int]]]:
    """
    写入数据标识符
    
    Returns:
        Optional[Tuple[bool, Optional[int]]]: (成功标志, NRC) 或 None
    """
    print(f"📤 写入DID 0x{did:04X}")
    request_data = [
        UDSServiceID.WRITE_DATA_BY_IDENTIFIER,
        (did >> 8) & 0xFF,
        did & 0xFF
    ] + data
    
    send_iso_tp_message(bus, arb_id, expected_response_ids, request_data, is_extend_id)
    response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
    
    if not response:
        return None
    
    expected_response = UDSServiceID.WRITE_DATA_BY_IDENTIFIER + ResponseCode.POSITIVE_RESPONSE_OFFSET
    if len(response) >= 3 and response[0] == expected_response:
        response_did = (response[1] << 8) | response[2]
        if response_did == did:
            return (True, None)
    
    elif len(response) >= 3 and response[0] == ResponseCode.NEGATIVE_RESPONSE:
        if response[1] == UDSServiceID.WRITE_DATA_BY_IDENTIFIER:
            nrc = response[2]
            return (False, nrc)
    
    return None

def scan_all_dids_mode0(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    is_extend_id: bool,
    start_did: int = 0x0000,
    end_did: int = 0xFFFF
) -> List[Tuple[int, Optional[List[int]], str]]:
    """扫描所有DID（读取模式）"""
    print(f"🔍 开始扫描 DID 范围: 0x{start_did:04X} 到 0x{end_did:04X}")
    print("="*80)
    print(f"{'DID':<8} {'HEX数据':<30} {'ASCII表示':<20} {'状态'}")
    print("-"*80)
    
    found_dids = []
    total = end_did - start_did + 1
    
    for idx, did in enumerate(range(start_did, end_did + 1), 1):
        try:
            result = read_data_by_identifier(bus, arb_id, expected_response_ids, did, is_extend_id)
            
            if result is None:
                pass
            elif result[0] is not None:
                data = result[0]
                hex_data = format_hex_data(data)
                ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
                print(f"0x{did:04X}   {hex_data:<30} {ascii_data:<20} 成功")
                found_dids.append((did, data, "success"))
            elif result[1] is not None:
                nrc = result[1]
                print(f"0x{did:04X}   {'NRC: 0x{:02X}'.format(nrc):<30} {'':<20} ", end="")
                print_nrc(nrc)
                found_dids.append((did, None, f"NRC: 0x{nrc:02X}"))
            
            if idx % 100 == 0:
                progress = (idx / total) * 100
                print(f"📊 进度: {idx}/{total} (0x{did:04X}/0x{end_did:04X}) - {progress:.1f}%")
            
            time.sleep(0.01)
            
        except KeyboardInterrupt:
            print("\n⚠️ 用户中断扫描")
            break
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
    
    # 保存结果
    try:
        with open("did_scan_results.txt", "w", encoding="utf-8") as f:
            f.write("DID扫描结果\n")
            f.write(f"{'DID':<8} {'HEX数据':<30} {'ASCII表示':<20} {'状态'}\n")
            f.write("-"*80 + "\n")
            
            for did, data, status in found_dids:
                if data is not None:
                    hex_data = format_hex_data(data)
                    ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
                    f.write(f"0x{did:04X}   {hex_data:<30} {ascii_data:<20} {status}\n")
                else:
                    f.write(f"0x{did:04X}   {'':<30} {'':<20} {status}\n")
        
        print(f"\n📄 详细结果已保存到 did_scan_results.txt")
    except Exception as e:
        print(f"⚠️ 保存结果失败: {e}")
    
    return found_dids

def test_write_did_mode1(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    is_extend_id: bool,
    start_did: int = 0x0000,
    end_did: int = 0xFFFF
) -> List[Tuple[int, str]]:
    """测试DID写入服务"""
    print(f"📝 开始测试 DID 写入服务，范围: 0x{start_did:04X} 到 0x{end_did:04X}")
    print("="*60)
    print(f"{'DID':<8} {'响应'}")
    print("-"*60)
    
    results = []
    test_data = [0x01, 0x02, 0x03, 0x04]
    total = end_did - start_did + 1
    
    for idx, did in enumerate(range(start_did, end_did + 1), 1):
        try:
            result = write_data_by_identifier(bus, arb_id, expected_response_ids, did, test_data, is_extend_id)
            
            if result is None:
                print(f"0x{did:04X}   无响应")
                results.append((did, "无响应"))
            elif result[0]:
                print(f"0x{did:04X}   写入成功")
                results.append((did, "写入成功"))
            elif result[1] is not None:
                nrc = result[1]
                print(f"0x{did:04X}   ", end="")
                print_nrc(nrc)
                results.append((did, f"NRC: 0x{nrc:02X}"))
            
            if idx % 50 == 0:
                progress = (idx / total) * 100
                print(f"📊 进度: {idx}/{total} (0x{did:04X}/0x{end_did:04X}) - {progress:.1f}%")
            
            time.sleep(0.02)
            
        except KeyboardInterrupt:
            print("\n⚠️ 用户中断测试")
            break
        except Exception as e:
            print(f"❌ DID 0x{did:04X}: 错误 - {e}")
            results.append((did, f"错误: {e}"))
            continue
    
    # 保存结果
    try:
        with open("write_did_test_results.txt", "w", encoding="utf-8") as f:
            f.write("DID写入测试结果\n")
            f.write(f"{'DID':<8} {'响应'}\n")
            f.write("-"*60 + "\n")
            
            for did, response in results:
                f.write(f"0x{did:04X}   {response}\n")
        
        print("="*60)
        print(f"✅ 测试完成，结果已保存到 write_did_test_results.txt")
    except Exception as e:
        print(f"⚠️ 保存结果失败: {e}")
    
    return results

# ==================== 内存读取 ====================
def read_memory(bus, start_address: int) -> None:
    """读取ECU内存"""
    is_fd = is_can_fd(bus)
    
    print(f"💾 读取内存地址: 0x{start_address:08X}")
    msg = can.Message(
        arbitration_id=DEFAULT_ARB_ID,
        data=[
            0x07, UDSServiceID.READ_MEMORY_BY_ADDRESS, 0x14,
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
    
    try:
        while True:
            response = bus.recv(timeout=DEFAULT_TIMEOUT)
            if response:
                data = response.data
                all_data.extend(data)
                
                try:
                    with open("hex_data.txt", "a", encoding="utf-8") as hex_file:
                        hex_file.write(format_hex_data(data) + '\n')
                except Exception as e:
                    print(f"⚠️ 写入文件失败: {e}")
                
                if len(data) < len(response.data):
                    break
            else:
                break
    except Exception as e:
        print(f"⚠️ 读取内存出错: {e}")
    
    ascii_string = ''.join(chr(b) for b in all_data if 32 <= b <= 126)
    print(f"📍 地址: {hex(start_address)}, ASCII: {ascii_string}")

# ==================== 用户输入函数 ====================
def print_log_header() -> None:
    """打印程序头部"""
    print("   .               .    ")
    print(" .´  ·  .     .  ·  `.  UDS TEST")
    print(" :  :  :  (¯)  :  :  :  A CAN Test Tool")
    print(" `.  ·  ` /¯\\ ´  ·  .´  by 1in-oos")
    print("   `     /¯¯¯\\     ´   https://github.com/1in-oos/seedtest.git")
    print("="*50)

def get_arbitration_id() -> int:
    """获取仲裁ID"""
    try:
        id_input = input("🔧 输入CAN消息ID (hex, 留空使用默认 7E0): ").strip()
        if id_input:
            return int(id_input, 16)
        return DEFAULT_ARB_ID
    except ValueError:
        print("❌ 输入格式错误，使用默认ID")
        return DEFAULT_ARB_ID

def get_response_ids(arb_id: int) -> Set[int]:
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
    return {arb_id + 8, arb_id - 8}

def get_uds_sid() -> int:
    """获取UDS服务ID"""
    try:
        sid_input = input("🔧 输入服务标识符 (hex, 留空使用默认 27): ").strip()
        if sid_input:
            return int(sid_input, 16)
        return DEFAULT_SID
    except ValueError:
        print("❌ 输入格式错误，使用默认SID")
        return DEFAULT_SID

def get_security_level() -> Tuple[int, int]:
    """获取安全访问级别和选择模式"""
    try:
        level_input = input("🔧 输入27安全访问级别 (hex, 留空使用默认 01): ").strip()
        level = int(level_input, 16) if level_input else DEFAULT_SECURITY_LEVEL
    except ValueError:
        print("❌ 输入格式错误，使用默认级别")
        level = DEFAULT_SECURITY_LEVEL
    
    seed_choice = get_seed_choice()
    return level, seed_choice

def get_seed_choice() -> int:
    """获取种子爆破模式选择"""
    print("\n🔧 选择种子爆破模式:")
    print("  0: 不进行爆破")
    print("  1: 随机密钥爆破")
    print("  2: 取反算法")
    print("  3: 多算法爆破")
    
    try:
        choice_input = input("请选择 (0-3, 默认 0): ").strip()
        if choice_input:
            choice = int(choice_input)
            if 0 <= choice <= 3:
                return choice
        return 0
    except ValueError:
        print("❌ 输入格式错误，使用默认模式0")
        return 0

def get_can_mode() -> bool:
    """获取CAN模式"""
    try:
        mode_input = input("🔧 选择CAN模式 (0: Classic CAN, 1: CAN FD, 默认 0): ").strip()
        if mode_input:
            mode = int(mode_input)
            if mode in [0, 1]:
                return bool(mode)
        return False
    except ValueError:
        print("❌ 输入格式错误，使用默认模式0 (Classic CAN)")
        return False

def get_did_scan_range() -> Tuple[int, int]:
    """获取DID扫描范围"""
    print("🔧 请输入要扫描的DID范围:")
    try:
        start_input = input("起始 DID (hex, 默认 0000): ").strip()
        end_input = input("结束 DID (hex, 默认 FFFF): ").strip()
        
        start_did = int(start_input, 16) if start_input else 0x0000
        end_did = int(end_input, 16) if end_input else 0xFFFF
        
        if start_did > end_did:
            print("❌ 起始DID不能大于结束DID，使用默认范围")
            return 0x0000, 0xFFFF
        
        return start_did, end_did
    except ValueError:
        print("❌ 输入格式错误，使用默认范围 0x0000-0xFFFF")
        return 0x0000, 0xFFFF

def get_scan_mode() -> int:
    """获取扫描模式"""
    try:
        mode_input = input("请选择模式 (0: 读取DID并显示数据, 1: 发送写入DID请求并返回NRC, 默认 0): ").strip()
        if mode_input:
            mode = int(mode_input)
            if mode in [0, 1]:
                return mode
        return 0
    except ValueError:
        print("❌ 输入格式错误，使用默认模式0")
        return 0

def get_target_address() -> Optional[int]:
    """获取目标地址（用于诊断激活）"""
    try:
        target_input = input("🔧 输入目标逻辑地址 (hex, 如: 0101): ").strip()
        if target_input:
            return int(target_input, 16)
        return None
    except ValueError:
        print("❌ 地址格式错误")
        return None

# ==================== 交互式模式 ====================
def send_custom_diagnostic_data(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    is_extend_id: bool
) -> None:
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
            
            try:
                hex_bytes = [int(b, 16) for b in cmd.split()]
                print(f"📤 发送: {format_hex_data(hex_bytes)}")
                
                send_iso_tp_message(bus, arb_id, expected_response_ids, hex_bytes, is_extend_id)
                response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
                
                if response:
                    print(f"📥 响应: {format_hex_data(response)}")
                    if len(response) >= 2 and response[0] == ResponseCode.NEGATIVE_RESPONSE:
                        if len(response) >= 3:
                            print_nrc(response[2])
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

def interactive_mode(
    bus,
    arb_id: int,
    expected_response_ids: Set[int],
    is_extend_id: bool
) -> None:
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
                stop_session_keep_alive()
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
                if keep_session_alive:
                    stop_session_keep_alive()
                else:
                    start_session_keep_alive(bus, arb_id, expected_response_ids, is_extend_id)
                continue
            
            if cmd == 'activate':
                target_addr = get_target_address()
                if target_addr:
                    activation_req = [
                        0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07,
                        (arb_id >> 8) & 0xFF, arb_id & 0xFF,
                        (target_addr >> 8) & 0xFF, target_addr & 0xFF,
                        0x00, 0x00, 0x00, 0x00
                    ]
                    print(f"📤 发送诊断激活请求: {format_hex_data(activation_req)}")
                else:
                    print("❌ 未提供目标地址")
                continue
            
            if cmd.startswith('session '):
                try:
                    session_type = int(cmd.split()[1], 16)
                    switch_session(bus, arb_id, expected_response_ids, is_extend_id, session_type)
                except (ValueError, IndexError) as e:
                    print(f"❌ 命令格式错误: {e}")
                continue
            
            if cmd.startswith('seed '):
                try:
                    level = int(cmd.split()[1], 16)
                    print(f"🔑 请求安全访问种子 (级别: 0x{level:02X})")
                    request_seed(bus, arb_id, expected_response_ids, level, is_extend_id, 1)
                except (ValueError, IndexError) as e:
                    print(f"❌ 命令格式错误: {e}")
                continue
            
            if cmd == 'reset':
                print("🔄 执行ECU硬重置")
                send_iso_tp_message(
                    bus, arb_id, expected_response_ids,
                    [UDSServiceID.ECU_RESET, 0x01],
                    is_extend_id
                )
                response = receive_iso_tp_message(bus, arb_id, expected_response_ids)
                if response:
                    print(f"📥 响应: {format_hex_data(response)}")
                continue
            
            if cmd:
                print("❌ 未知命令，输入 'help' 查看帮助")
                
        except KeyboardInterrupt:
            print("\n👋 收到中断信号，退出...")
            stop_session_keep_alive()
            break
        except EOFError:
            print("\n👋 输入结束，退出...")
            stop_session_keep_alive()
            break

# ==================== 主函数 ====================
def main() -> None:
    """主函数"""
    print_log_header()
    
    # 获取配置
    arb_id = get_arbitration_id()
    response_ids = get_response_ids(arb_id)
    sid = get_uds_sid()
    is_extend_id = arb_id > CAN_STD_ID_MAX
    use_fd = get_can_mode()
    
    # 创建CAN过滤器
    filters = [create_can_filter(resp_id) for resp_id in response_ids]
    filters.append(create_can_filter(arb_id))
    
    # 初始化CAN总线
    bus = None
    try:
        bus_kwargs = {
            "channel": DEFAULT_CHANNEL,
            "interface": DEFAULT_INTERFACE,
            "can_filters": filters
        }
        
        if use_fd:
            bus_kwargs["fd"] = True
            print("✅ 使用 CAN FD 模式")
        else:
            print("✅ 使用 Classic CAN 模式")
        
        bus = can.interface.Bus(**bus_kwargs)
    except Exception as e:
        print(f"❌ 初始化CAN总线失败: {e}")
        return
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        if sid == UDSServiceID.SECURITY_ACCESS:
            level, seed_choice = get_security_level()
            
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
                    if seed:
                        process_seed_invert(bus, arb_id, response_ids, level, seed, is_extend_id)
                
                elif seed_choice == 3:
                    print("🧠 请求种子并进行多算法爆破")
                    auto_seed_key_attack(bus, arb_id, response_ids, level, is_extend_id)
                    
            except KeyboardInterrupt:
                print("\n👋 用户中断操作...")
            finally:
                stop_session_keep_alive()
                
        elif sid == UDSServiceID.READ_MEMORY_BY_ADDRESS:
            start_address = 0xC3F80000
            try:
                read_memory(bus, start_address)
                time.sleep(0.1)
            except KeyboardInterrupt:
                print("\n👋 用户中断操作...")
                
        elif sid == UDSServiceID.READ_DATA_BY_IDENTIFIER:
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
        else:
            # 进入交互模式
            print("🎮 进入交互诊断模式")
            extended_session(bus, arb_id, response_ids, is_extend_id)
            interactive_mode(bus, arb_id, response_ids, is_extend_id)
            
    finally:
        stop_session_keep_alive()
        if bus:
            bus.shutdown()

if __name__ == "__main__":
    main()
