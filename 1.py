arb_id = 0x18da17f9

# 执行字节交换操作交换3和4字节
arb_id = (arb_id & 0xFFFF0000) | ((arb_id & 0x0000FF00) >> 8) | ((arb_id & 0x000000FF) << 8)

# 打印结果
print(hex(arb_id))  # 应该打印出 0x18daf917 



