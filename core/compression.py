import zlib

class StreamCompression:
    """
    轻量高速流式分块压缩与解压缩算子
    采用标准 zlib deflate 算法，兼具高压缩比与极高吞吐速度
    """
    @staticmethod
    def compress_chunk(data, level=6):
        if not data:
            return b""
        try:
            return zlib.compress(data, level)
        except Exception:
            return data

    @staticmethod
    def decompress_chunk(compressed_data):
        if not compressed_data:
            return b""
        try:
            return zlib.decompress(compressed_data)
        except Exception:
            return compressed_data
