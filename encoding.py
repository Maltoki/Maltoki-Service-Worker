import struct


def decode_list(data:bytes) -> list[int|float]:
    signed, bytes_type, data = struct.unpack("?", data[:1]), {"I":int, "F":float}[data[1:2].decode()], data[2:]

    type_str = ""

    if bytes_type == int:
        type_str = "q" if signed else "Q"
    elif bytes_type == float:
        type_str = "d"
    
    assert type_str in "qQd", "Invalid type."

    return list(struct.unpack(type_str * (len(data) // 8), data[:len(data)-(len(data) % 8)]))
        

    
def encode_list(data:list[int|float], signed:bool = True) -> bytes:
    assert len(data) != 0, "Attempt to send empty data"
    assert isinstance(data[0], (int, float)), "Data must be either integer or floating point values"
    
    result = struct.pack("?", signed)

    if isinstance(data[0], int):
        result += "I".encode()
    if isinstance(data[0], float):
        result += "F".encode()

    if isinstance(data[0], float):
        result += struct.pack(f"{len(data)}d", *data)
    elif isinstance(data[0], int):
        result += struct.pack(str(len(data)) + ("q" if signed else "Q"), *data)

    return result