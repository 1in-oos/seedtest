from scipy.stats import chisquare

def read_seed_log(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()    #读取文件有多少行
        data = [line.strip().split()[:len(line.strip().split()) // 2] for line in lines]
        #data = [line.strip().split() for line in lines]  #删除头和尾的空格  按照空格分割成单词列表
        #print(data)
        return data

def count_row_occurrences(data):
    # 创建一个空字典来存储每行数据出现的次数
    row_counts = {}

    # 遍历数据列表中的每一行
    for row in data:
        # 将当前行转换为元组，以便在字典中使用
        row_tuple = tuple(row)

        # 更新字典中当前行的出现次数
        row_counts[row_tuple] = row_counts.get(row_tuple, 0) + 1

    # 输出每行数据的出现次数
    #for row, count in row_counts.items():
        #print(f"Row {row}: Occurrences: {count}/{len(data)}")
    print("每个值的重复次数")
    print(" ".join(f"{count}" for index, count in row_counts.items()))
    print(f"出现不重复总个数： {len(row_counts)}/{len(data)}")

def check_randomness(data):
    num_groups = len(data)      #每行
    num_entries = len(data[0])  #每个字节
    total_p_value = 0

    for i in range(num_entries):
        observed_counts = [int(entry[i], 16) for entry in data]     

        observed_counts = [observed_counts.count(val) for val in range(256)]    #计算每个实际次数
        #print(observed_counts)
        expected_counts = [len(data) / 256] *256   #计算每个数值期望的次数 
        #print(expected_counts)
        chi2, p_value = chisquare(observed_counts, f_exp=expected_counts)   #计算卡方值和P值

        # 将小于 0.0000000001 的 p-value 设为 0
        if p_value < 0.0000000001:
            p_value = 0

        total_p_value += p_value

        print(f"Comparison of Byte {i + 1} across {num_groups} groups:")
        print(f"Chi-squared value: {chi2}")
        print(f"P-value: {p_value}")
        print(f"Is random: {'Yes' if p_value > 0.05 else 'No'}")

    avg_p_value = total_p_value / num_entries
    print(f"Average P-value across bytes: {avg_p_value}")
    print(f"Overall randomness: {'Random' if avg_p_value > 0.05 else 'Not random'}")

if __name__ == "__main__":
    file_path = "logs/seed-bcm修改前4.25.log"
    data = read_seed_log(file_path)
    #check_randomness(data)  # 调用函数检查数据随机性
    count_row_occurrences(data)     # 调用函数并传入数据列表
