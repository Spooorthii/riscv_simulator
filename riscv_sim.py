import json
import random

def execute_instructions(reg_val, instructions):
    results = []
    for instruction in instructions:
        if instruction['instrn'] == 'add':
            result = reg_val[instruction['src_reg1']] + reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'sub':
            result = reg_val[instruction['src_reg1']] - reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'and':
            result = reg_val[instruction['src_reg1']] & reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'or':
            result = reg_val[instruction['src_reg1']] | reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'slt':
            result = reg_val[instruction['src_reg1']] < reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'addi':
            imm = instruction.get('imm', 0) 
            result = reg_val[instruction['src_reg1']] + imm
        elif instruction['instrn'] == 'slti':
            imm = instruction.get('imm', 0)  
            result = reg_val[instruction['src_reg1']] < imm
        elif instruction['instrn'] == 'sltiu':
            imm = instruction.get('imm', 0)  
            result = reg_val[instruction['src_reg1']] < imm
        elif instruction['instrn'] == 'xori':
            imm = instruction.get('imm', 0)  
            result = reg_val[instruction['src_reg1']] ^ imm
        elif instruction['instrn'] == 'ori':
            imm = instruction.get('imm', 0)  
            result = reg_val[instruction['src_reg1']] | imm
        elif instruction['instrn'] == 'andi':
            imm = instruction.get('imm', 0)  
            result = reg_val[instruction['src_reg1']] & imm
        elif instruction['instrn'] == 'sltu':
            result = reg_val[instruction['src_reg1']] < reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'slli':
            imm = instruction.get('imm', 0)  
            result = reg_val[instruction['src_reg1']] << imm
        elif instruction['instrn'] == 'srli':
            imm = instruction.get('imm', 0)  
            result = reg_val[instruction['src_reg1']] >> imm
        elif instruction['instrn'] == 'srai':
            imm = instruction.get('imm', 0) 
            result = reg_val[instruction['src_reg1']] >> imm
        elif instruction['instrn'] == 'sll':
            result = reg_val[instruction['src_reg1']] << reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'srl':
            result = reg_val[instruction['src_reg1']] >> reg_val[instruction['src_reg2']]
        elif instruction['instrn'] == 'sra':
            result = reg_val[instruction['src_reg1']] >> reg_val[instruction['src_reg2']]
        else:
            result = 0
        results.append(result)
        imm_m = f", imm:{bin(instruction.get('imm', 0))}" if 'imm' in instruction else ""
        src_reg2_r = f", src_reg2:{bin(instruction.get('src_reg2', 0))}" if 'src_reg2' in instruction else ""
        print(f"instrn:{instruction['instrn']}, src_reg1:{instruction['src_reg1']}{src_reg2_r}{imm_m}, output={bin(result)}")
        
    return results

reg_val = {
    "x0": 0,
    "x1": random.randint(0, 10),
    "x2": random.randint(0, 10),
    "x3": random.randint(0, 10),
    "x4": random.randint(0, 10),
    "x5": random.randint(0, 10),
    "x6": random.randint(0, 10),
    "x7": random.randint(0, 10),
    "x8": random.randint(0, 10),
    "x9": random.randint(0, 10),
    "x10": random.randint(0, 10),
    "x11": random.randint(0, 10),
    "x12": random.randint(0, 10),
    "x13": random.randint(0, 10),
    "x14": random.randint(0, 10),
    "x15": random.randint(0, 10),
    "x16": random.randint(0, 10),
    "x17": random.randint(0, 10),
    "x18": random.randint(0, 10),
    "x19": random.randint(0, 10),
    "x20": random.randint(0, 10),
    "x21": random.randint(0, 10),
    "x22": random.randint(0, 10),
    "x23": random.randint(0, 10),
    "x24": random.randint(0, 10),
    "x25": random.randint(0, 10),
    "x26": random.randint(0, 10),
    "x27": random.randint(0, 10),
    "x28": random.randint(0, 10),
    "x29": random.randint(0, 10),
    "x30": random.randint(0, 10),
    "x31": random.randint(0, 10),
}

with open('input.json', 'r') as openfile:
    json_object = json.load(openfile)

all_results = execute_instructions(reg_val, json_object)
print("All instructions output:", all_results)
import random

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

def decode_opcode(opcode):
    opcode_int = int(opcode, 16)
    opcode = f"{(opcode_int & 0b1111111):07b}"
    rd = f"{(opcode_int >> 7) & 0b11111:05b}"
    fun = f"{(opcode_int >> 12) & 0b111:03b}"
    rs1 = f"{(opcode_int >> 15) & 0b11111:05b}"
    imm = f"{(opcode_int >> 20) & 0b111111111111:012b}"
    imm_int = int(imm, 2)
    if imm_int >= 2048:
        imm_int -= 4096
    return opcode, rd, fun, rs1, imm_int

def main():
    reg_val = {f"x{i}": random.randint(0, 10) for i in range(31)}
    with open('tr.txt', "r") as file:
        for line in file:
            opcode = extract_opcode(line)
            imm_val = extract_imm_value(line)
            opcode, rd, fun, rs1, imm = decode_opcode(opcode)
            
            if opcode == '0010011' and fun == '000':  # Opcode '0010011' with function '000' is addi.
                rd_val = reg_val[f"x{int(rd, 2)}"]
                rs1_val = reg_val[f"x{int(rs1, 2)}"]
                result = rs1_val + imm_val
                print("This is 'addi' instruction.")
                print(f"Decoded Values: opcode: {opcode}, rd: x{int(rd, 2)}, fun: {fun}, rs1: x{int(rs1, 2)}, imm: {imm_val}")
                print(f"Register Values: x{int(rd, 2)} = {rd_val}, x{int(rs1, 2)} = {rs1_val}")
                print(f"Result: x{int(rd, 2)} = x{int(rs1, 2)} + {imm_val} = {result}")

            # Add more if conditions for other opcodes and functions here.
            # For example:
            elif opcode == '0110011' and fun == '000':  # Opcode '0110011' with function '000' is add.
                rd_val = reg_val[f"x{int(rd, 2)}"]
                rs1_val = reg_val[f"x{int(rs1, 2)}"]
                result = rs1_val + reg_val[f"x{int(imm, 2)}"]  # Note: Using imm as a register index for 'add'.
                print("This is 'add' instruction.")
                print(f"Decoded Values: opcode: {opcode}, rd: x{int(rd, 2)}, fun: {fun}, rs1: x{int(rs1, 2)}, imm: x{int(imm, 2)}")
                print(f"Register Values: x{int(rd, 2)} = {rd_val}, x{int(rs1, 2)} = {rs1_val}")
                print(f"Result: x{int(rd, 2)} = x{int(rs1, 2)} + x{int(imm, 2)} = {result}")

if __name__ == "__main__":
    main()
