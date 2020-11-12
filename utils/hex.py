#############################################

# print(hex_string_to_hex_value("7CA58265"))
# print(int("0x" + "7CA58265", 16))
# bytearray.fromhex(hex_string_to_hex_value("7CA58265"))
# print binascii.unhexlify(hex_string_to_hex_value("7CA58265"))

class HexUtil:
    @staticmethod
    def hex_string_to_bin_string(input):
        lookup = {"0": "0000", "1": "0001", "2": "0010", "3": "0011", "4": "0100", "5": "0101", "6": "0110",
                  "7": "0111", "8": "1000", "9": "1001", "A": "1010", "B": "1011", "C": "1100", "D": "1101",
                  "E": "1110", "F": "1111"}
        result = ""
        for byte in input:
            result = result + lookup[byte]
        return result

    @staticmethod
    def hex_string_to_hex_value(input):
        value = HexUtil.hex_string_to_bin_string(input)
        highest_order = len(value) - 1
        result = 0
        for bit in value:
            result = result + int(bit) * pow(2, highest_order)
            highest_order = highest_order - 1
        return hex(result)

    @staticmethod
    def hex_string_format(input):
        return r"\\x" + r"\\x".join(input[n: n + 2] for n in range(0, len(input), 2))
