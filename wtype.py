import random

def decode_rtype_opcode(opcode_int):
    opcode = f"{(opcode_int & 0b1111111):07b}"
    rd = f"{(opcode_int >> 7) & 0b11111:05b}"
    fun = f"{(opcode_int >> 12) & 0b111:03b}"
    rs1 = f"{(opcode_int >> 15) & 0b11111:05b}"
    rs2 = f"{(opcode_int >> 20) & 0b11111:05b}"
    return opcode, rd, fun, rs1, rs2

def decode_itype_opcode(opcode_int):
    opcode = f"{(opcode_int & 0b1111111):07b}"
    rd = f"{(opcode_int >> 7) & 0b11111:05b}"
    fun = f"{(opcode_int >> 12) & 0b111:03b}"
    rs1 = f"{(opcode_int >> 15) & 0b11111:05b}"
    imm = f"{(opcode_int >> 20) & 0b111111111111:012b}"
    imm_int = int(imm, 2)
    if imm_int >= 2048:
        imm_int -= 4096
    return opcode, rd, fun, rs1, imm_int

def extract_opcode(instruction_line):
    start_index = instruction_line.find("(") + 1
    end_index = instruction_line.find(")")
    opcode = instruction_line[start_index:end_index]
    return opcode

def extract_imm_value(instruction_line):
    start_index = instruction_line.find(", ") + 2
    imm_str = instruction_line[start_index:].split(',')[1].strip()
    imm = int(imm_str)
    return imm


def decode_opcode(instruction_line):
    parts = instruction_line.split()
    opcode_hex = parts[3].replace('(', '').replace(')', '')
    opcode_int = int(opcode_hex, 16)
    opcode_bits = f"{(opcode_int & 0b1111111):07b}"

    if opcode_bits == '0010011':
        opcode, rd, fun, rs1, imm = decode_itype_opcode(opcode_int)
        rs2 = None
    elif opcode_bits == '0110011':
        opcode, rd, fun, rs1, rs2 = decode_rtype_opcode(opcode_int)
        imm = None
    elif opcode_bits == '0111011':
        opcode, rd, fun, rs1, rs2 = decode_rtype_opcode(opcode_int)
        imm = None
    elif opcode_bits == '0011011':
        opcode, rd, fun, rs1, imm = decode_itype_opcode(opcode_int)
        rs2 = None
    else:
        opcode, rd, fun, rs1, rs2, imm = None, None, None, None, None, None

    rd = f"x{int(rd, 2)}"
    rs1 = f"x{int(rs1, 2)}"
    if rs2 is not None:
        rs2 = f"x{int(rs2, 2)}"

    return opcode, rd, fun, rs1, rs2, imm

def main():
    reg_val = {f"x{i}": random.randint(0, 10) for i in range(32)}
    with open('tr.txt', "r") as file:
        for line in file:
            if any(instr in line for instr in ['addi', 'and', 'slti', 'xori', 'sltu', 'sra', 'srli', 'xor', 'srl', 'add','slli','sltiu', 'slt','sub','sll','srai' ,'andi', 'addw', 'srlw', 'sllw', 'srliw']):
                opcode = bin(int(extract_opcode(line), 16))
                print('type  opcode', (opcode))
                opcode, rd, fun, rs1, rs2, imm = decode_opcode(line)
                rd_val_int = reg_val[rd]                
                rs1_val_int = reg_val[rs1]
                if rs2 is not None:
                    rs2_val_int = reg_val[rs2]

                if opcode == '0010011' and fun == '000':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int + imm
                    reg_val[rd] = result
                    instruction_name = 'addi'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} + {imm_val}"

                elif opcode == '0110011' and fun == '111':
                    result = rs1_val_int & rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'and'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} & {rs2}:{rs2_val_int}"

                elif opcode == '0111011' and fun == '010':
                    result = rs1_val_int << rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'sllw'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} << {rs2}:{rs2_val_int}"

                elif opcode == '0011011' and fun == '101':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int >> imm_val
                    reg_val[rd] = result
                    instruction_name = 'srliw'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {imm_val}"

                else:
                    result_str = "unknown instruction"
                    instruction_name = "unknown"
                    operands = ""

                print(f"{instruction_name}:{operands}")
                print(f"{result_str}")
                print(f"rd: {reg_val[rd]}\n")

if __name__ == "__main__":
    main()
