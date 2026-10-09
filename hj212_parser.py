"""
HJ212-2017 协议报文解析器
=========================
实现 HJ212-2017 环境监测数据传输标准的报文解析功能。

报文格式：
    ## + 4位长度(ASCII十进制) + 数据段 + 4位CRC(ASCII十六进制) + \r\n

CRC16 参数：
    初始值：0xFFFF
    多项式：0xA001
    校验范围：长度字段 + 数据段

作者：蔡雨欣 (202410760213)
"""

import json
import re


class HJ212Parser:
    """HJ212-2017 协议报文解析类"""

    # 报文结构常量
    HEADER = '##'
    TAIL = '\r\n'
    LENGTH_LEN = 4       # 长度字段占4个字符
    CRC_LEN = 4          # CRC字段占4个字符

    # CRC16 参数
    CRC_INIT = 0xFFFF
    CRC_POLY = 0xA001

    def is_valid_message(self, message):
        """
        检查报文格式是否正确。

        参数:
            message (str): 完整的HJ212报文字符串（含##头和\r\n尾）

        返回:
            bool: 格式正确返回True，否则返回False
        """
        if not message or not isinstance(message, str):
            return False

        # 检查头部和尾部
        if not message.startswith(self.HEADER):
            return False
        if not message.endswith(self.TAIL):
            return False

        # 检查最短长度：## + 4位长度 + 4位CRC + \r\n
        min_len = len(self.HEADER) + self.LENGTH_LEN + self.CRC_LEN + len(self.TAIL)
        if len(message) < min_len:
            return False

        # 提取并验证长度字段
        length_str = message[len(self.HEADER):len(self.HEADER) + self.LENGTH_LEN]
        if not length_str.isdigit():
            return False
        data_length = int(length_str)

        # 计算期望的总长度
        expected_total = (len(self.HEADER) + self.LENGTH_LEN +
                          data_length + self.CRC_LEN + len(self.TAIL))
        if len(message) != expected_total:
            return False

        # 验证CRC字段是否为合法十六进制
        crc_start = len(self.HEADER) + self.LENGTH_LEN + data_length
        crc_str = message[crc_start:crc_start + self.CRC_LEN]
        try:
            int(crc_str, 16)
        except ValueError:
            return False

        return True

    def _crc16(self, data_bytes):
        """
        计算ANSI CRC16校验值。

        参数:
            data_bytes (bytes): 待校验的字节数据

        返回:
            int: CRC16校验值（16位无符号整数）
        """
        crc = self.CRC_INIT
        for byte in data_bytes:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ self.CRC_POLY
                else:
                    crc >>= 1
        return crc & 0xFFFF

    def validate_crc(self, message):
        """
        校验报文的CRC值是否正确。

        参数:
            message (str): 完整的HJ212报文字符串

        返回:
            bool: CRC校验通过返回True，失败返回False
        """
        if not self.is_valid_message(message):
            return False

        # 计算CRC的范围：从长度字段第一个字符到数据段最后一个字符
        # 即 message[2 : -6]（去掉##头和CRC+\r\n尾）
        crc_data_str = message[len(self.HEADER):-(self.CRC_LEN + len(self.TAIL))]
        crc_expected = message[-(self.CRC_LEN + len(self.TAIL)):-len(self.TAIL)]

        # 计算实际CRC
        actual_crc = self._crc16(crc_data_str.encode('ascii'))
        actual_crc_str = f"{actual_crc:04X}"

        return actual_crc_str == crc_expected.upper()

    def parse_data_segment(self, message):
        """
        解析数据段，返回包含所有键值对的字典。

        参数:
            message (str): 完整的HJ212报文字符串

        返回:
            dict: 数据段中所有键值对的字典，解析失败返回空字典
        """
        if not self.is_valid_message(message):
            return {}

        # 提取数据段
        length_str = message[len(self.HEADER):len(self.HEADER) + self.LENGTH_LEN]
        data_length = int(length_str)
        data_start = len(self.HEADER) + self.LENGTH_LEN
        data_segment = message[data_start:data_start + data_length]

        # 解析键值对（分号分隔）
        result = {}
        pairs = data_segment.split(';')
        for pair in pairs:
            pair = pair.strip()
            if '=' in pair:
                key, value = pair.split('=', 1)
                result[key.strip()] = value.strip()

        return result

    def extract_monitoring_data(self, message):
        """
        从CP字段中提取所有监测因子及其数值。

        参数:
            message (str): 完整的HJ212报文字符串

        返回:
            dict: 监测因子字典，键为因子编码，值为对应数值
        """
        data_segment = self.parse_data_segment(message)
        if not data_segment:
            return {}

        cp_str = data_segment.get('CP', '')
        if not cp_str:
            return {}

        # 尝试解析CP中的JSON数据
        monitoring = {}
        try:
            cp_obj = json.loads(cp_str)
        except json.JSONDecodeError:
            # 如果不是标准JSON，尝试按原始格式解析
            return self._parse_cp_raw(cp_str)

        # CP中通常包含 Data 字段，内含逗号分隔的因子数据
        data_str = cp_obj.get('Data', '')
        if not data_str:
            return {}

        # 解析逗号分隔的因子键值对
        factors = data_str.split(',')
        for factor in factors:
            factor = factor.strip()
            if '=' in factor:
                key, value = factor.split('=', 1)
                monitoring[key.strip()] = value.strip()

        return monitoring

    def _parse_cp_raw(self, cp_str):
        """
        以原始格式解析CP字段（处理非JSON格式的情况）。

        参数:
            cp_str (str): CP字段字符串

        返回:
            dict: 解析出的监测因子字典
        """
        monitoring = {}
        # 尝试提取 &&Data=...&& 格式
        match = re.search(r'Data=(.+?)(?:&&|$)', cp_str)
        if match:
            data_str = match.group(1)
            factors = data_str.split(',')
            for factor in factors:
                factor = factor.strip()
                if '=' in factor:
                    key, value = factor.split('=', 1)
                    monitoring[key.strip()] = value.strip()
        return monitoring

    def get_message_info(self, message):
        """
        获取报文的完整解析信息（综合方法）。

        参数:
            message (str): 完整的HJ212报文字符串

        返回:
            dict: 包含格式校验、CRC校验、数据段、监测数据的综合信息
        """
        info = {
            'format_valid': self.is_valid_message(message),
            'crc_valid': False,
            'data_segment': {},
            'monitoring_data': {}
        }

        if info['format_valid']:
            info['crc_valid'] = self.validate_crc(message)
            info['data_segment'] = self.parse_data_segment(message)
            info['monitoring_data'] = self.extract_monitoring_data(message)

        return info
