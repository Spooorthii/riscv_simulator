import random 
import array

reg_val = {f"x{i}": random.randint(0, 10) for i in range(32)}
memory_values = array.array('i', [random.randint(0, 2000) for _ in range(2000)])

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

def decode_stype_opcode(opcode_int):
    opcode = f"{(opcode_int & 0b1111111):07b}"
    imm1 = f"{(opcode_int >> 7) & 0b11111:05b}"
    fun = f"{(opcode_int >> 12) & 0b111:03b}"
    rs1 = f"{(opcode_int >> 15) & 0b11111:05b}"
    rs2 = f"{(opcode_int >> 20) & 0b11111:05b}"
    imm2 = f"{(opcode_int >> 25) & 0b1111111:07b}"
    immm = imm1 + imm2
    imm_int = int(immm, 2)
    if imm_int >= 2048:
        imm_int -= 4096
    return opcode, fun, rs1,rs2, imm_int

def extract_opcode(instruction_line):
    start_index = instruction_line.find("(") + 1
    end_index = instruction_line.find(")")
    opcode = instruction_line[start_index:end_index]
    return opcode

def extract_imm_value(instruction_line):
    imm_start = instruction_line.rfind(", ") + 2
    imm_str = instruction_line[imm_start:].split("(")[0].strip()
    imm = int(imm_str)
    return imm

def store_memory(rs1, imm, rs2):
    memory_address = (reg_val[rs1] + imm)%2000
    mem = memory_address
    memory_values[memory_address] = reg_val[rs2]

def store_half_memory(rs1, imm, rs2):
    memory_address = (reg_val[rs1] + imm)%2000
    mem = memory_address
    original_value = memory_values[memory_address]
    reg_val[rs2] = (original_value & 0xFFFF0000) | (reg_val[rs2] & 0xFFFF)
    memory_values[memory_address] = reg_val[rs2]

def load_word_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm)%2000
    mem = memory_address
    reg_val[rd] = int(memory_values[memory_address])

def load_byte_unsigned_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm)%2000
    mem = memory_address
    reg_val[rd] = int(memory_values[memory_address] & 0xFF)

def load_half_unsigned_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm)%2000
    reg_val[rd] = int(memory_values[memory_address] & 0xFFFF)

def load_half_signed_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm)%2000
    mem = memory_address
    original_value = memory_values[memory_address]
    sign_bit = original_value & 0x8000
    if sign_bit != 0:
        reg_val[rd] = int(original_value | 0xFFFF0000)
    else:
        reg_val[rd] = int(original_value & 0xFFFF)

def load_byte_signed_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm)%2000
    mem = memory_address
    original_value = memory_values[memory_address]
    sign_bit = original_value & 0x80
    if sign_bit != 0:
        reg_val[rd] = int(original_value | 0xFFFFFF00)
    else:
        reg_val[rd] = int(original_value & 0xFF)

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

    elif opcode_bits == '0000011':
        opcode, rd, fun, rs1, imm = decode_itype_opcode(opcode_int)
        rs2 = None

    elif opcode_bits == '0100011':
        opcode, fun, rs1, rs2, imm_int = decode_stype_opcode(opcode_int)
        rd = None
        rs1 = f"x{int(rs1, 2)}"
        rs2 = f"x{int(rs2, 2)}"
        return opcode, rd, fun, rs1, rs2, imm_int
    else:
        opcode, rd, fun, rs1, rs2, imm = None, None, None, None, None, None

    if rd is not None:
        rd = f"x{int(rd, 2)}"
    if rs1 is not None:
        rs1 = f"x{int(rs1, 2)}"
    if rs2 is not None:
        rs2 = f"x{int(rs2, 2)}"

    return opcode, rd, fun, rs1, rs2, imm

def main():
    instruction_mappings = {

        #('0011011', '000'): ('srliw', 'itype', 'alu', '>>', lambda rs1, imm: int(rs1 >> imm)),
        #('0011011', '000'): ('sraiw', 'itype', 'alu', '<<', lambda rs1, imm: int(rs1 >> imm)),
        #('0011011', '000'): ('slliw', 'itype', 'alu', '>>', lambda rs1, imm: int(rs1 << imm)),
        #('0111011', '111'): ( 'srlw', 'rtype', 'alu', '>>', lambda rs1, rs2: int(rs1 >> rs2)),
        #('0110011', '101'): (  'sra', 'rtype', 'alu', '>>', lambda rs1, rs2: int(rs1 >> rs2)),
        #('0110011', '101'): (  'srl', 'rtype', 'alu', '>>', lambda rs1, rs2: int(rs1 >> rs2)),
        ('0010011', '101'): ( 'srli', 'itype', 'alu', '>>', lambda rs1, imm: int(rs1 >> imm)),
        ('0010011', '001'): ( 'slli', 'itype', 'alu', '<<', lambda rs1, imm: int(rs1 << imm)),
        ('0010011', '000'): ( 'addi', 'itype', 'alu',  '+', lambda rs1, imm: int(rs1  + imm)),
        ('0010011', '010'): ( 'slti', 'itype', 'alu',  '<', lambda rs1, imm: int(rs1  < imm)),
        ('0010011', '100'): ( 'xori', 'itype', 'alu',  '^', lambda rs1, imm: int(rs1  ^ imm)),
        ('0010011', '011'): ('sltiu', 'itype', 'alu',  '<', lambda rs1, imm: int(rs1  < imm)),
        ('0010011', '101'): ( 'srai', 'itype', 'alu', '>>', lambda rs1, imm: int(rs1 >> imm)),
        ('0010011', '111'): ( 'andi', 'itype', 'alu',  '&', lambda rs1, imm: int(rs1  & imm)),
        ('0010011', '110'): (  'ori', 'itype', 'alu',  '|', lambda rs1, imm: int(rs1  | imm)),
        ('0011011', '000'): ('addiw', 'itype', 'alu',  '+', lambda rs1, imm: int(rs1  + imm)),
        ('0111011', '111'): ( 'addw', 'rtype', 'alu',  '+', lambda rs1, rs2: int(rs1  + rs2)),
        ('0111011', '111'): ( 'sllw', 'rtype', 'alu', '<<', lambda rs1, rs2: int(rs1 << rs2)),
        ('0111011', '111'): ( 'subw', 'rtype', 'alu',  '-', lambda rs1, rs2: int(rs1  - rs2)),
        ('0110011', '111'): (  'and', 'rtype', 'alu',  '&', lambda rs1, rs2: int(rs1  & rs2)),
        ('0110011', '011'): ( 'sltu', 'rtype', 'alu',  '<', lambda rs1, rs2: int(rs1  < rs2)),
        ('0110011', '100'): (  'xor', 'rtype', 'alu',  '^', lambda rs1, rs2: int(rs1  ^ rs2)),
        ('0110011', '000'): (  'add', 'rtype', 'alu',  '+', lambda rs1, rs2: int(rs1  + rs2)),
        ('0110011', '010'): (  'slt', 'rtype', 'alu',  '<', lambda rs1, rs2: int(rs1  < rs2)),
        ('0110011', '000'): (  'sub', 'rtype', 'alu',  '-', lambda rs1, rs2: int(rs1  - rs2)),
        ('0110011', '001'): (  'sll', 'rtype', 'alu', '<<', lambda rs1, rs2: int(rs1 << rs2)),
        ('0110011', '110'): (   'or', 'rtype', 'alu',  '|', lambda rs1, rs2: int(rs1  | rs2)),
        ('0000011', '010'): (  ' lw', 'itype', 'lsu',   '', lambda rs1, imm, rd: load_word_memory(rs1, imm, rd )),
        ('0000011', '100'): (  'lbu', 'itype', 'lsu',   '', lambda rs1, imm, rd: load_byte_unsigned_memory(rs1, imm, rd)),
        ('0000011', '101'): (  'lhu', 'itype', 'lsu',   '', lambda rs1, imm, rd: load_half_unsigned_memory(rs1, imm, rd)),
        ('0000011', '001'): (   'lh', 'itype', 'lsu',   '', lambda rs1, imm, rd: load_half_signed_memory(rs1, imm, rd)),
        ('0000011', '000'): (   'lb', 'itype', 'lsu',   '', lambda rs1, imm, rd: load_byte_signed_memory(rs1, imm, rd)),
        ('0100011', '010'): (   'sw', 'stype', 'lsu',   '', lambda rs1, imm, rs2: store_memory(rs1, imm, rs2)),
        ('0100011', '001'): (   'sh', 'stype', 'lsu',   '', lambda rs1, imm, rs2: store_half_memory(rs1, imm, rs2))
    }

    with open('tr.txt', "r") as file:
        for line in file:
            instructions_to_check = ['addi', 'and', 'slti', 'xori', 'sltu',  'srli', 'xor','slliw',
                                      'add', 'slli', 'sltiu', 'slt', 'sub', 'sll', 'srai', 'srlw',
                                     'andi', 'ori', 'addiw' , 'addw', 'sllw','srliw','sraiw', 'sra',
                                      'subw', 'lw', 'lbu', 'lhu', 'lh', 'lb', 'sw', 'sh','srl']
            if any(instr in line for instr in instructions_to_check):
                opcode = extract_opcode(line)
                opcode = bin(int(extract_opcode(line), 16))
                print('type  opcode', (opcode))
                opcode, rd, fun, rs1, rs2, imm = decode_opcode(line)

                key = (opcode, fun)
                if key in instruction_mappings:
                    instruction_name, inst_type, inst_kind, char_oper, operation = instruction_mappings[key]
                    if imm is not None:
                        operands = f"{rd}, {rs1}, {imm}" 
                    elif rd is not None:
                        operands = f"{rd}, {rs1}, {rs2}"
                    else:
                        operands = f"{rs2}, {rs1}, {imm}"

                    if inst_type == 'itype' and inst_kind == 'alu':
                        result = operation(reg_val[rs1], imm)
                        reg_val[rd] = result
                        operands_str = f"{instruction_name} {operands}"       
                        result_str = f"{rd} = {rs1}:{reg_val[rs1]} {char_oper} {imm}"
                        print(operands_str)
                        print(result_str)
                        print(f"{rd}:{result}")
                    elif inst_type == 'rtype' and inst_kind == 'alu':
                        result = operation(reg_val[rs1], reg_val[rs2])
                        reg_val[rd] = result
                        operands_str = f"{instruction_name} {operands}"       
                        result_str = f"{rd} = {rs1}:{reg_val[rs1]} {char_oper}  {rs2}:{reg_val[rs2]}"
                        print(operands_str)
                        print(result_str)
                        print(f"{rd}:{result}")
                    elif inst_type == 'itype' and inst_kind == 'lsu':
                        result = operation(rs1, imm, rd)
                        operands_str = f"{instruction_name} {rd},{imm}({rs1})"   
                        rs1_str = f"{rs1}:{reg_val[rs1]}"
                        memory = reg_val[rs1]+imm % 2000
                        print(operands_str)
                        print(f"{rs1}:{rs1_str} mem:{memory}")
                        rd_str = f"{rd}: {reg_val[rd]}"
                        print(rd_str)
                    elif inst_type == 'stype' and inst_kind == 'lsu':
                        result = operation(rs1, imm, rs2)
                        operands_str = f"{instruction_name} {rs2},{imm}({(rs1)})"  
                        rs1_str = f"{rs1}:{reg_val[rs1]}"
                        memory = reg_val[rs1]+imm % 2000
                        print(operands_str)
                        print(f"{rs1}:{rs1_str} mem:{memory}")
                        rs2_str = f"{rs2}: {reg_val[rs2]}"
                        print(rs2_str)
                    print("\n\n")
if __name__ == "__main__":
    main()

