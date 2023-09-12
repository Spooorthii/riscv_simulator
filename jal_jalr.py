import json
jal_instruction = {
        'opcode':'jal',
        'rd':'dest_reg',
        'address':'target_register'
        }
jalr_instruction = {
        'opcode':'jalr',
        'rd':'dest_reg',
        'rs1':'src_reg1',
        'imm_val':'offset'
        }
jal_instruction_json = json.dumps(jal_instruction,indent=4) 
jalr_instruction_json = json.dumps(jal_instruction,indent=4)
print(jal_instruction_json)
print(jalr_instruction_json)




#import random
#def extract_opcode
#    start_index = instruction_line.find("(") + 1
#    end_index = instruction_line.find(")")
#    opcode = instruction_line[start_index:end_index]
#    return opcode
#def extract_imm_value(instruction_line):
#    start_index = instruction_line.find(", ") + 2
#    imm_str = instruction_line[start_index:].split(',')[1].strip()
#    imm = int(imm_str)
#    return imm
#def decode_opcode(opcode):
#    opcode_int = int(opcode, 16)
#    opcode = f"{(opcode_int & 0b1111111):07b}"
#    rd = f"{(opcode_int >> 7) & 0b11111:05b}"
#    fun = f"{(opcode_int >> 12) & 0b111:03b}"
#    rs1 = f"{(opcode_int >> 15) & 0b11111:05b}"
#    imm = f"{(opcode_int >> 20) & 0b111111111111:012b}"
#    imm_int = int(imm, 2)
#    if imm_int >= 2048:
#        imm_int -= 4096
#    return opcode, rd, fun, rs1, imm_int
#
#def main():
#    reg_val = {f"x{i}": random.randint(0, 10) for i in range(31)}
#    with open('tr.txt', "r") as file:
#        for line in file:
#            if "addi" in line:
#                start_line = line.strip().split()
#                opcode = extract_opcode(start_line[3])
#                imm_val = extract_imm_value(line)
#                opcode, rd, fun, rs1, imm = decode_opcode(opcode)
#                if opcode == '0010011' and fun == '000':
#                    rd_val = reg_val[f"x{int(rd, 2)}"]
#                    rs1_val = reg_val[f"x{int(rs1, 2)}"]
#                    result = rs1_val + imm_val
#                    print("This is 'addi' instruction.")
#                    print(f"Decoded Values: opcode: {opcode}, rd: x{int(rd, 2)}, fun: {fun}, rs1: x{int(rs1, 2)}, imm: {imm_val}")
#                    print(f"Register Values: x{int(rd, 2)} = {rd_val}, x{int(rs1, 2)} = {rs1_val}")
#                    print(f"Result: x{int(rd, 2)} = x{int(rs1, 2)} + {imm_val} = {result}")  
#  
#if __name__ == "__main__":
#    main()

