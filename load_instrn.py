import random
def load_instructions(reg_val,instruction):
    imm = instruction['imm']
    target_reg = instruction['target_reg']
    memory_address = reg_val['pc']+imm
    value_from_memory = random.randint(0,100)
    reg_val[target_reg] = value_from_memory
    reg_val['pc'] += imm

reg_val = {
        'pc':100,
        'x1':0,
        'x2':10,
        'x3':20,
        'x4':30,
        'x5':50
        }
instruction_load = {
        'instrn':'load',
        'imm':5,
        'target_reg':'x1'
        }
load_instructions(reg_val,instruction_load)
print("value loaded into x1:",reg_val['x1'])



elif opcode == '0110011' and fun == '100':
                    result = rs1_val_int ^ rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'xor'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} ^ {rs2}:{rs2_val_int}"

                elif opcode == '0110011' and fun == '110':
                    result = rs1_val_int | rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'or'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} | {rs2}:{rs2_val_int}"

                elif opcode == '0110011' and fun == '000':
                    result = rs1_val_int - rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'sub'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} - {rs2}:{rs2_val_int}"
                    
                elif opcode == '0110011' and fun == '000':
                    result = rs1_val_int + rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'add'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} + {rs2}:{rs2_val_int}"

                elif opcode == '0110011' and fun == '010':
                    result = rs1_val_int < rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'slt'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} < {rs2}:{rs2_val_int}"

                elif opcode == '0110011' and fun == '001':
                    result = rs1_val_int << rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'sll'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} << {rs2}:{rs2_val_int}"

                elif opcode == '0010011' and fun == '001':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int << imm_val
                    reg_val[rd] = result
                    instruction_name = 'slli'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} << {imm_val}"

                elif opcode == '0010011' and fun == '110':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int | imm_val
                    reg_val[rd] = result
                    instruction_name = 'ori'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} | {imm_val}"

                elif opcode == '0010011' and fun == '101':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int >> imm_val
                    reg_val[rd] = result
                    instruction_name = 'srai'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {imm_val}"


#load instruction

import random 

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

#def decode_stype_opcode(opcode_int):
    #opcode = f"{(opcode_int & 0b1111111):07b}"
    #imm1 = f"{(opcode_int >> 7) & 0b11111:05b}"
    #fun = f"{(opcode_int >> 12) & 0b111:03b}"
    #rs1 = f"{(opcode_int >> 15) & 0b11111:05b}"
    #rs2 = f"{(opcode_int >> 20) & 0b11111:05b}"
    #imm2 = f"{(opcode_int >> 25) & 0b1111111:07b}"
    #immm = imm1 + imm2
    #imm_int = int(immm, 2)
    #if imm_int >= 2048:
        #imm_int -= 4096
    #return opcode, fun, rs1,rs2, imm_int


def extract_opcode(instruction_line):
    start_index = instruction_line.find("(") + 1
    end_index = instruction_line.find(")")
    opcode = instruction_line[start_index:end_index]
    return opcode

def extract_imm_value(instruction_line):
    imm_str = instruction_line.split(',')[1].strip()
    imm_parts = imm_str.split('(')  
    imm_num = imm_parts[0].strip()  
    imm = int(imm_num)
    return imm

def extract_memory_address(instruction_line):
    open_index = instruction_line.find("(")
    close_index = instruction_line.find(")")
    memory_address_str = instruction_line[open_index + 1:close_index]
    memory_address = int(memory_address_str,16)
    return memory_address

def decode_opcode(instruction_line):
    parts = instruction_line.split()
    opcode_hex = parts[3].replace('(', '').replace(')', '')
    opcode_int = int(opcode_hex, 16)
    opcode_bits = f"{(opcode_int & 0b1111111):07b}"

    if opcode_bits == '0000011':
        opcode, rd, fun, rs1, imm = decode_itype_opcode(opcode_int)
        rs2 = None  
        rd = f"x{int(rd, 2)}"
        rs1 = f"x{int(rs1, 2)}"
        if rs2 is not None:
            rs2 = f"x{int(rs2, 2)}"
        return opcode, rd, fun, rs1, rs2, imm

    #elif opcode_bits == '0100011':
        #opcode, fun, rs1, rs2, imm_int = decode_stype_opcode(opcode_int) 
        #rd = None
        #rs1 = f"x{int(rs1, 2)}"
        #rs2 = f"x{int(rs2, 2)}"
        #return opcode, fun, rs1, rs2, imm_int

def main():
    reg_val = {f"x{i}": random.randint(0, 10) for i in range(32)}
    #memory_values = {f"address_{i}": random.randint(0, 100) for i in range(1001)}
    with open('trace.txt', "r") as p:
        for line in p:
            if any(instr in line for instr in ['lw','lbu','lhu','lh','lb']):
                opcode = bin(int(extract_opcode(line), 16))[2:].zfill(32)
                opcode_type = opcode[:7]
                print('type  opcode:', opcode_type, opcode)
                opcode, rd, fun, rs1, rs2, imm = decode_opcode(line)
                if opcode:
                    rd_val_int = reg_val[rd]
                    rs1_val_int = reg_val[rs1]
                    if rs2 is not None:
                        rs2_val_int = reg_val[rs2]

                    if opcode == '0000011' and fun == '010':
                        imm_val = extract_imm_value(line)
                        result = (rs1_val_int + imm) & 0xFFFF
                        reg_val[rd] = result
                        instruction_name = 'lw'
                        operands = f"{rd}, {rs1}, {imm_val}"
                        result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val}) & 0xFFFF"

                    elif opcode == '0000011' and fun == '100':
                        imm_val = extract_imm_value(line)
                        result = (rs1_val_int + imm) & 0xF
                        reg_val[rd] = result
                        instruction_name = 'lbu'
                        operands = f"{rd}, {rs1}, {imm_val}"
                        result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val}) & 0xF"

                    elif opcode == '0000011' and fun == '101':
                        imm_val = extract_imm_value(line)
                        result = (rs1_val_int + imm) & 0xFF 
                        reg_val[rd] = result
                        instruction_name = 'lhu'
                        operands = f"{rd}, {rs1}, {imm_val}"
                        result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val}) & 0xFF"

                    elif opcode == '0000011' and fun == '001':
                        imm_val = extract_imm_value(line)
                        result = rs1_val_int + imm
                        reg_val[rd] = result
                        instruction_name = 'lh'
                        operands = f"{rd}, {rs1}, {imm_val}"
                        result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val})"

                    elif opcode == '0000011' and fun == '000':
                        imm_val = extract_imm_value(line)
                        result = rs1_val_int + imm
                        reg_val[rd] = result
                        instruction_name = 'lb'
                        operands = f"{rd}, {rs1}, {imm_val}"
                        result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val})"
                     
                    else:
                        result_str = "unknown instruction"
                        instruction_name = "unknown"
                        operands = ""
                else:
                    result_str = "unknown instruction"
                    instruction_name = "unknown"
                    operands = ""

                print(f"{instruction_name}:{operands}")
                print(f"{result_str}")
                print(f"{rd}: {reg_val[rd]}")
                memory_address = extract_memory_address(line)
                print("memory address:", hex(memory_address))
                print()                
if __name__ == "__main__":
    main()





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


"""def decode_stype_opcode(opcode_int):
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
    return opcode, fun, rs1,rs2, imm_int"""


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

#lsj
"""def extract_imm_value(instruction_line):
    imm_str = instruction_line.split(',')[1].strip()
    imm_parts = imm_str.split('(')  
    imm_num = imm_parts[0].strip()  
    imm = int(imm_num)
    return imm

def extract_memory_address(instruction_line):
    open_index = instruction_line.find("(")
    close_index = instruction_line.find(")")
    memory_address_str = instruction_line[open_index + 1:close_index]
    memory_address = int(memory_address_str,16)
    return memory_address"""


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


    """elif opcode_bits == '0000011':
        opcode, rd, fun, rs1, imm = decode_itype_opcode(opcode_int)
        rs2 = None  
        rd = f"x{int(rd, 2)}"
        rs1 = f"x{int(rs1, 2)}"
        if rs2 is not None:
            rs2 = f"x{int(rs2, 2)}"
        return opcode, rd, fun, rs1, rs2, imm
    elif opcode_bits == '0100011':
        opcode, fun, rs1, rs2, imm_int = decode_stype_opcode(opcode_int) 
        rd = None
        rs1 = f"x{int(rs1, 2)}"
        rs2 = f"x{int(rs2, 2)}"
        return opcode, rd, fun, rs1, rs2, imm_int"""  

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
             if any(instr in line for instr in ['addi', 'and', 'slti', 'xori', 'sltu', 'sra', 'srli', 'xor', 'srl', 'add','slli','sltiu', 'slt','sub','sll','srai' ,'andi', 'addiw','srlw','srliw', 'addw', 'sllw','sraiw','slliw','subw', 'lw', 'lbu', 'lhu', 'lh', 'lb', 'sw', 'sh' ]):
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

                elif opcode == '0010011' and fun == '010':
                    imm_val = extract_imm_value(line)
                    result = int(rs1_val_int < imm_val)  
                    reg_val[rd] = result
                    instruction_name = 'slti'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} < {imm_val}"
                    result_str += f" ({result})"

                elif opcode == '0010011' and fun == '100':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int ^ imm_val
                    reg_val[rd] = result
                    instruction_name = 'xori'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} ^ {imm_val}"

                elif opcode == '0110011' and fun == '011':
                    result = int(rs1_val_int < rs2_val_int)  
                    reg_val[rd] = result
                    instruction_name = 'sltu'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} < {rs2}:{rs2_val_int} ({result})"

                elif opcode == '0110011' and fun == '101':
                    result = rs1_val_int >> rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'sra'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {rs2}:{rs2_val_int}"

                elif opcode == '0010011' and fun == '101':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int >> imm_val
                    reg_val[rd] = result
                    instruction_name = 'srli'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {imm_val}"

                elif opcode == '0110011' and fun == '100':
                    result = rs1_val_int ^ rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'xor'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} ^ {rs2}:{rs2_val_int}"

                elif opcode == '0110011' and fun == '101':
                    result = rs1_val_int >> rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'srl'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {rs2}:{rs2_val_int}"
                    
                elif opcode == '0110011' and fun == '000':
                    result = rs1_val_int + rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'add'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} + {rs2}:{rs2_val_int}"

                elif opcode == '0010011' and fun == '001':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int << imm_val
                    reg_val[rd] = result
                    instruction_name = 'slli'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} << {imm_val}"

                elif opcode == '0010011' and fun == '011':
                    imm_val = extract_imm_value(line)
                    result = int(rs1_val_int < imm_val)
                    reg_val[rd] = result
                    instruction_name = 'sltiu'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} < {imm_val}"
                    result_str += f" ({result})"


                elif opcode == '0110011' and fun == '010':
                    result = int(rs1_val_int < rs2_val_int)
                    reg_val[rd] = result
                    instruction_name = 'slt'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} < {rs2}:{rs2_val_int} ({result}) "

                elif opcode == '0010011' and fun == '101':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int >> imm_val
                    reg_val[rd] = result
                    instruction_name = 'srai'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {imm_val}"

                elif opcode == '0110011' and fun == '110':
                    result = rs1_val_int | rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'or'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} | {rs2}:{rs2_val_int}"

                elif opcode == '0010011' and fun == '110':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int | imm_val
                    reg_val[rd] = result
                    instruction_name = 'ori'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} | {imm_val}"

                elif opcode == '0110011' and fun == '000':
                    result = rs1_val_int - rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'sub'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} - {rs2}:{rs2_val_int}"

                elif opcode == '0110011' and fun == '001':
                    result = rs1_val_int << rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'sll'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} << {rs2}:{rs2_val_int}"

                elif opcode == '0010011' and fun == '111':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int & imm_val
                    reg_val[rd] = result
                    instruction_name = 'andi'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} & {imm_val}"

                elif opcode == '0011011' and fun == '000':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int + imm
                    reg_val[rd] = result
                    instruction_name = 'addiw'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} + {imm_val}"

                elif opcode == '0111011' and fun == '101':
                    result = rs1_val_int >> rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'srlw'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {rs2}:{rs2_val_int}"

                elif opcode == '0011011' and fun == '101':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int >> imm_val
                    reg_val[rd] = result
                    instruction_name = 'srliw'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {imm_val}"

                elif opcode == '0111011' and fun == '000':
                    result = rs1_val_int + rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'addw'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} + {rs2}:{rs2_val_int}"

                elif opcode == '0111011' and fun == '001':
                    result = rs1_val_int << rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'sllw'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} << {rs2}:{rs2_val_int}"

                elif opcode == '0011011' and fun == '101':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int >> imm_val
                    reg_val[rd] = result
                    instruction_name = 'sraiw'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} >> {imm_val}"

                elif opcode == '0011011' and fun == '001':
                    imm_val = extract_imm_value(line)
                    result = rs1_val_int << imm_val
                    reg_val[rd] = result
                    instruction_name = 'slliw'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} << {imm_val}"

                elif opcode == '0111011' and fun == '000':
                    result = rs1_val_int - rs2_val_int
                    reg_val[rd] = result
                    instruction_name = 'subw'
                    operands = f"{rd}, {rs1}, {rs2}"
                    result_str = f"{rd}={rs1}:{rs1_val_int} - {rs2}:{rs2_val_int}"
                
                """elif opcode == '0000011' and fun == '010':
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val
                    loaded_value = memory_values.get(f"address_{memory_address}", 0)
                    instruction_name = 'lw'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val}) & 0xFFFF"
                    loaded_value_str = f"{rd}: {loaded_value}"
                    registers[rd] = loaded_value

                elif opcode == '0000011' and fun == '100':
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val
                    loaded_value = memory_values.get(f"address_{memory_address}", 0)
                    instruction_name = 'lbu'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val}) & 0xFF"
                    loaded_value_str = f"{rd}: {loaded_value}"
                    registers[rd] = loaded_value

                elif opcode == '0000011' and fun == '101':
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val
                    loaded_value = memory_values.get(f"address_{memory_address}", 0) & 0xFFF
                    instruction_name = 'lhu'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val}) & 0xFFF"
                    loaded_value_str = f"{rd}: {loaded_value}"
                    registers[rd] = loaded_value

                elif opcode == '0000011' and fun == '001':
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val
                    loaded_value = memory_values.get(f"address_{memory_address}", 0) & 0xFFFF
                    instruction_name = 'lh'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val})"
                    loaded_value_str = f"{rd}: {loaded_value}"
                    registers[rd] = loaded_value

                elif opcode == '0000011' and fun == '000':
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val
                    loaded_value = memory_values.get(f"address_{memory_address}", 0) 
                    instruction_name = 'lb'
                    operands = f"{rd}, {rs1}, {imm_val}"
                    result_str = f"{rd} = ({rs1}:{rs1_val_int} + {imm_val})"
                    loaded_value_str = f"{rd}: {loaded_value}"
                    registers[rd] = loaded_value

                elif opcode == '0100011' and fun == '010':
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val
                    loaded_value = memory_values.get(f"address_{memory_address}", 0)
                    instruction_name = 'sw'
                    operands = f"{rs2}, {rs1}, {imm_val}"
                    memory_values[memory_address] = loaded_value
                    result_str = f"({rs1}:{rs1_val_int} + {imm_val})"
                    rs2 = f"{rs2}:{loaded_value}"
                    

                elif opcode == '0100011' and fun == '001':
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val
                    loaded_value = memory_values.get(f"address_{memory_address}", 0)
                    instruction_name = 'sh'
                    operands = f"{rs2}, {rs1}, {imm_val}"
                    memory_values[memory_address] = loaded_value
                    result_str = f"({rs1}:{rs1_val_int} + {imm_val})"
                    rs2 = f"{rs2}:{loaded_value}" """

                else:
                    result_str = "unknown instruction"
                    instruction_name = "unknown"
                    operands = ""

                print(f"{instruction_name}:{operands}")
                print(f"{result_str}")
                print(f"rd: {reg_val[rd]}\n")
                

                """print(f"{instruction_name}:{operands}")
                print(f"{result_str}")
                print(f"{loaded_value_str}")
                memory_address = extract_memory_address(line)
                print("memory address:", hex(memory_address))
                print(rs2)
                print()"""


if __name__ == "__main__":
    main()





elif opcode in ['0000011', '0100011']:
                    imm_val = extract_imm_value(line)
                    rs1_val_int = int(rs1[1:])
                    memory_address = rs1_val_int + imm_val

                    if opcode == '0000011':
                        loaded_value = memory_values[memory_address]
                        if fun == '010':
                            instruction_name = 'lw'
                            registers[rd] = loaded_value
                        elif fun == '100':
                            instruction_name = 'lbu'
                            registers[rd] = loaded_value & 0xFF
                        elif fun == '101':
                            instruction_name = 'lhu'
                            registers[rd] = loaded_value & 0xFFFF
                        elif fun == '001':
                            instruction_name = 'lh'
                            load_half_signed_memory(rs1, imm_val, rd)  
                        elif fun == '000':
                            instruction_name = 'lb'
                            load_byte_signed_memory(rs1, imm_val, rd)  

                        if loaded_value is not None and fun != '001' and fun != '000':
                            result_str = f"{rd} {rs1}:{rs1_val_int} + {imm_val}"
                            print(f"Memory Address: {memory_address}")
                            print(f"{instruction_name}: {result_str} = {registers[rd]}")
                        elif fun == '001' or fun == '000':
                            print(f"Memory Address: {memory_address}")
                            print(f"{instruction_name}: {registers[rd]}")
                        else:
                            print(f"{instruction_name}: Unknown function code")

                    elif opcode == '0100011':
                        if fun == '010':
                            store_memory(rs1, imm_val, rs2)
                            print(f"Stored value {registers[rs2]} at memory address {reg_val[rs1] + imm_val}")
                        elif fun == '001':
                            store_half_memory(rs1, imm_val, rs2)
                            print(f"Stored half value {registers[rs2]} at memory address {reg_val[rs1] + imm_val}")
                        else:
                            print("Unknown function code")

if __name__ == "__main__":
    main()



