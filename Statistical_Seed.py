from scipy.stats import chisquare

def read_seed_log(file_path):
    """读取日志文件并转换为二维十六进制数组"""
    with open(file_path, 'r') as file:
        lines = [line.strip() for line in file if line.strip()]
        data = [line.split() for line in lines]
    #print(data)
    return data


def count_row_occurrences(data):
    """统计每一行是否有重复"""
    # 创建字典统计每行出现次数
    row_counts = {}
    for row in data:
        row_tuple = tuple(row)
        row_counts[row_tuple] = row_counts.get(row_tuple, 0) + 1

    print("重复的数值及出现次数：")
    duplicates = {row: count for row, count in row_counts.items() if count > 1}
    
    if duplicates:
        for row, count in duplicates.items():
            print(f"{' '.join(row)} : 出现 {count} 次")
    else:
        print("没有重复的行。")

    print(f"唯一行数量：{len(row_counts)} / 总行数：{len(data)}")


def check_randomness(data):
    """用卡方检验检测每个字节分布是否接近均匀"""
    num_groups = len(data)      # 行数
    num_entries = len(data[0])  # 每行字节数
    total_p_value = 0

    for i in range(num_entries):
        # 取第 i 个字节列
        observed_values = [int(entry[i], 16) for entry in data]
        # 计算每个字节值出现次数（0~255）
        observed_counts = [observed_values.count(val) for val in range(256)]
        expected_counts = [len(data) / 256] * 256

        chi2, p_value = chisquare(observed_counts, f_exp=expected_counts)
        if p_value < 1e-10:
            p_value = 0
        total_p_value += p_value

        print(f"\nByte {i + 1} 分布检验:")
        print(f"Chi-squared 值: {chi2:.4f}")
        print(f"P-value: {p_value:.6g}")
        print(f"是否随机: {'是' if p_value > 0.05 else '否'}")

    avg_p_value = total_p_value / num_entries
    print(f"\n平均 P-value: {avg_p_value:.6g}")
    print(f"总体结论: {'随机' if avg_p_value > 0.05 else '非随机'}")


if __name__ == "__main__":
    file_path = "logs/seed-zhiji.log_hex"
    data = read_seed_log(file_path)

    # 查看重复行
    count_row_occurrences(data)

    # 检查随机性
    #check_randomness(data)
