"""
HJ212Parser 测试用例
===================
验证 HJ212-2017 协议报文解析器的各项功能。

作者：蔡雨欣 (202410760213)
"""

from hj212_parser import HJ212Parser


def build_test_message():
    """
    构造一个标准的HJ212测试报文，包含正确的CRC值。

    报文结构：## + 4位长度 + 数据段 + 4位CRC + \r\n
    """
    parser = HJ212Parser()

    # 数据段内容
    data_segment = (
        'QN=20261009103000001;'
        'ST=32;'
        'CN=2011;'
        'PW=123456;'
        'MN=88888000000001;'
        'Flag=4;'
        'CP={"Data":"a01001-Rtd=0.123,a01001-Flag=N,a01001-Avg=0.120,'
        'a01007-Rtd=15.6,a01007-Flag=N,a06001-Rtd=45.2,a06001-Flag=N"}'
    )

    # 长度字段（4位ASCII十进制）
    length_str = f"{len(data_segment):04d}"

    # 计算CRC（校验范围：长度字段 + 数据段）
    crc_input = (length_str + data_segment).encode('ascii')
    crc_value = parser._crc16(crc_input)
    crc_str = f"{crc_value:04X}"

    # 组装完整报文
    message = '##' + length_str + data_segment + crc_str + '\r\n'
    return message


def test_is_valid_message():
    """测试报文格式校验功能"""
    parser = HJ212Parser()
    message = build_test_message()

    print("=" * 60)
    print("测试1：报文格式校验 (is_valid_message)")
    print("=" * 60)

    # 正常报文
    result = parser.is_valid_message(message)
    print(f"  正常报文校验: {'通过' if result else '失败'}")

    # 缺少头部
    bad_msg1 = message[2:]
    result = parser.is_valid_message(bad_msg1)
    print(f"  缺少'##'头部: {'正确拒绝' if not result else '错误通过'}")

    # 缺少尾部
    bad_msg2 = message.rstrip('\r\n')
    result = parser.is_valid_message(bad_msg2)
    print(f"  缺少'\\r\\n'尾部: {'正确拒绝' if not result else '错误通过'}")

    # 长度字段非数字
    bad_msg3 = '##AAAA' + message[6:]
    result = parser.is_valid_message(bad_msg3)
    print(f"  长度字段非数字: {'正确拒绝' if not result else '错误通过'}")

    # 空报文
    result = parser.is_valid_message("")
    print(f"  空报文: {'正确拒绝' if not result else '错误通过'}")

    print()


def test_validate_crc():
    """测试CRC校验功能"""
    parser = HJ212Parser()
    message = build_test_message()

    print("=" * 60)
    print("测试2：CRC校验 (validate_crc)")
    print("=" * 60)

    # 正确的CRC
    result = parser.validate_crc(message)
    print(f"  正确CRC校验: {'通过' if result else '失败'}")

    # 篡改数据段中的一个字符
    length_str = message[2:6]
    data_len = int(length_str)
    data_segment = message[6:6 + data_len]
    crc_part = message[6 + data_len:]

    # 修改数据段中的一个字符（将0改为1）
    modified_data = data_segment.replace('0.123', '9.999', 1)
    bad_msg = '##' + length_str + modified_data + crc_part
    result = parser.validate_crc(bad_msg)
    print(f"  篡改数据段后CRC校验: {'正确拒绝' if not result else '错误通过'}")

    # 篡改CRC值
    crc_hex = message[6 + data_len:6 + data_len + 4]
    bad_crc = 'FFFF' if crc_hex != 'FFFF' else '0000'
    bad_msg2 = message[:6 + data_len] + bad_crc + message[6 + data_len + 4:]
    result = parser.validate_crc(bad_msg2)
    print(f"  篡改CRC值后校验: {'正确拒绝' if not result else '错误通过'}")

    print()


def test_parse_data_segment():
    """测试数据段解析功能"""
    parser = HJ212Parser()
    message = build_test_message()

    print("=" * 60)
    print("测试3：数据段解析 (parse_data_segment)")
    print("=" * 60)

    data = parser.parse_data_segment(message)
    print(f"  解析到的字段数: {len(data)}")
    for key in ['QN', 'ST', 'CN', 'PW', 'MN', 'Flag', 'CP']:
        if key in data:
            print(f"    {key} = {data[key][:50]}{'...' if len(data[key]) > 50 else ''}")
        else:
            print(f"    {key} = (缺失)")

    print()


def test_extract_monitoring_data():
    """测试监测数据提取功能"""
    parser = HJ212Parser()
    message = build_test_message()

    print("=" * 60)
    print("测试4：监测因子提取 (extract_monitoring_data)")
    print("=" * 60)

    monitoring = parser.extract_monitoring_data(message)
    print(f"  提取到的监测因子数: {len(monitoring)}")
    for key, value in monitoring.items():
        print(f"    {key} = {value}")

    print()


def test_get_message_info():
    """测试综合解析功能"""
    parser = HJ212Parser()
    message = build_test_message()

    print("=" * 60)
    print("测试5：综合解析 (get_message_info)")
    print("=" * 60)

    info = parser.get_message_info(message)
    print(f"  格式校验: {'通过' if info['format_valid'] else '失败'}")
    print(f"  CRC校验:  {'通过' if info['crc_valid'] else '失败'}")
    print(f"  数据段字段数: {len(info['data_segment'])}")
    print(f"  监测因子数: {len(info['monitoring_data'])}")

    print()


def main():
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          HJ212-2017 报文解析器 - 测试报告             ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    message = build_test_message()
    print(f"测试报文示例：")
    print(f"  {message[:80]}{'...' if len(message) > 80 else ''}")
    print(f"  报文总长度: {len(message)} 字符")
    print()

    test_is_valid_message()
    test_validate_crc()
    test_parse_data_segment()
    test_extract_monitoring_data()
    test_get_message_info()

    print("=" * 60)
    print("所有测试完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
