
from elftools.elf.elffile import ELFFile
import os
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_32

instruction_mappings = {
    ('0111011', '111', '0000000'): ('add', 'rtype', 'alu', '+', lambda rs1, rs2: int(rs1 + rs2)),
    ('0111011', '111', '0000001'): ('mul', 'rtype', 'alu', '*', lambda rs1, rs2: int(rs1 * rs2)),
    ('0111011', '111', '0000100'): ('sub', 'rtype', 'alu', '-', lambda rs1, rs2: int(rs1 - rs2)),
    ('0111011', '111', '0001000'): ('xor', 'rtype', 'alu', '^', lambda rs1, rs2: int(rs1 ^ rs2)),
    ('0111011', '111', '0001100'): ('div', 'rtype', 'alu', '/', lambda rs1, rs2: int(rs1 / rs2)),
    ('0111011', '111', '0010000'): ('srl', 'rtype', 'alu', '>>', lambda rs1, rs2: int(rs1 >> rs2)),
    ('0111011', '111', '0010100'): ('sra', 'rtype', 'alu', '>>', lambda rs1, rs2: int(rs1 >> rs2)),
    ('0111011', '111', '0011000'): ('or', 'rtype', 'alu', '|', lambda rs1, rs2: int(rs1 | rs2)),
    ('0111011', '111', '0011100'): ('rem', 'rtype', 'alu', '%', lambda rs1, rs2: int(rs1 % rs2)),
    ('0111011', '111', '0100000'): ('and', 'rtype', 'alu', '&', lambda rs1, rs2: int(rs1 & rs2)),
    # I-type instructions
    ('0010011', '101'): ('srli', 'itype', 'alu', '>>', lambda rs1, imm: int(rs1 >> imm)),
    ('0010011', '001'): ('slli', 'itype', 'alu', '<<', lambda rs1, imm: int(rs1 << imm)),
    ('0010011', '000'): ('addi', 'itype', 'alu', '+', lambda rs1, imm: int(rs1 + imm)),
    ('0010011', '010'): ('slti', 'itype', 'alu', '<', lambda rs1, imm: 1 if rs1 < imm else 0),
    ('0010011', '100'): ('xori', 'itype', 'alu', '^', lambda rs1, imm: int(rs1 ^ imm)),
    ('0010011', '011'): ('sltiu', 'itype', 'alu', '<', lambda rs1, imm: 1 if rs1 < imm else 0),
    ('0010011', '101'): ('srai', 'itype', 'alu', '>>', lambda rs1, imm: int(rs1 >> imm)),
    ('0010011', '111'): ('andi', 'itype', 'alu', '&', lambda rs1, imm: int(rs1 & imm)),
    ('0010011', '110'): ('ori', 'itype', 'alu', '|', lambda rs1, imm: int(rs1 | imm)),
    ('0011011', '000'): ('addiw', 'itype', 'alu', '+', lambda rs1, imm: int(rs1 + imm)),
    # S-type instructions
    ('0100011', '010'): ('sw', 'stype', 'lsu', '', None),
    ('0100011', '001'): ('sh', 'stype', 'lsu', '', None),
    # Load instructions
    ('0000011', '010'): ('lw', 'itype', 'lsu', '', None),  
    ('0000011', '100'): ('lbu', 'itype', 'lsu', '', None),
    ('0000011', '101'): ('lhu', 'itype', 'lsu', '', None),
    ('0000011', '001'): ('lh', 'itype', 'lsu', '', None),
    ('0000011', '000'): ('lb', 'itype', 'lsu', '', None),  
    # J-type instructions
    ('1101111', '000'): ('jal', 'jtype', 'ctrl', '', None),
    # I-type instructions
    ('1100111', '000'): ('jalr', 'itype', 'ctrl', '', None),
    # B-type instructions
    ('1100011', '000'): ('beq', 'btype', 'ctrl', '', None),
    ('1100011', '001'): ('bne', 'btype', 'ctrl', '', None),
    ('1100011', '100'): ('blt', 'btype', 'ctrl', '', None),
    ('1100011', '101'): ('bge', 'btype', 'ctrl', '', None),
    ('1100011', '110'): ('bltu', 'btype', 'ctrl', '', None),
    ('1100011', '111'): ('bgeu', 'btype', 'ctrl', '', None),
    # U-type instructions
    ('0110111', '0000000'): ('lui', 'utype', 'alu', '', None),
    # UJ-type instructions
    ('1101111', '0000000'): ('jal', 'ujtype', 'ctrl', '', None)

}

class ElfFileProcessor:
    def __init__(self):
        self.memory = {}
        self.registers = {}

    def read_memory(self, address, size):
        data = b""
        for i in range(size):
            data += bytes([self.memory.get(address + i, 0)])
        return data

    def write_memory(self, address, data):
        for i, byte in enumerate(data):
            self.memory[address + i] = byte

    def perform_instruction(self, instruction):
        opcode = instruction[:7]
        funct3 = instruction[12:15]
        funct7 = instruction[25:32]

        if (opcode, funct3, funct7) in instruction_mappings:
            instr_info = instruction_mappings[(opcode, funct3, funct7)]
            instruction_name = instr_info[0]
            instr_type = instr_info[1]
            instr_category = instr_info[2]
            operand_type = instr_info[3]
            operation = instr_info[4]

            print(f"Instruction: {instruction_name}")
            print(f"Type: {instr_type}")
            print(f"Category: {instr_category}")
            print(f"Operand Type: {operand_type}")

            if instr_type == 'rtype':
                rs1 = int(instruction[20:25], 2)
                rs2 = int(instruction[7:12], 2)

                rs1_value = self.registers.get(rs1, 0)
                rs2_value = self.registers.get(rs2, 0)

                result = operation(rs1_value, rs2_value)
                print(f"Result: {result}")
                rd = int(instruction[20:25], 2)
                self.registers[rd] = result

            elif instr_type == 'itype':
                rs1 = int(instruction[20:25], 2)
                rs1_value = self.registers.get(rs1, 0)
                imm = int(instruction[0:12], 2)
                if imm & 0x800:
                    imm |= 0xFFFFF000  

                if operation:
                    result = operation(rs1_value, imm)
                    print(f"Result: {result}")
                    rd = int(instruction[20:25], 2)
                    self.registers[rd] = result

            elif instr_type == 'stype':
                rs1 = int(instruction[20:25], 2)
                rs2 = int(instruction[7:12], 2)
                rs1_value = self.registers.get(rs1, 0)
                rs2_value = self.registers.get(rs2, 0)
                imm = int(instruction[0:7] + instruction[25:32], 2)

                if operation:
                    result = operation(rs1_value, rs2_value, imm)
                    print(f"Result: {result}")

                    if instr_category == 'lsu':
                        if instruction_name == 'sw':
                            address = rs1_value + imm
                            data = result.to_bytes(4, byteorder='little')
                            self.write_memory(address, data)
                        elif instruction_name == 'sh':
                            address = rs1_value + imm
                            data = result.to_bytes(2, byteorder='little')
                            self.write_memory(address, data)

                    elif instr_category == 'lsu':
                        if instruction_name == 'lw':
                            address = rs1_value + imm
                            data = self.read_memory(address, 4)
                            result = int.from_bytes(data, byteorder='little', signed=True)
                        elif instruction_name == 'lbu':
                            address = rs1_value + imm
                            data = self.read_memory(address, 1)
                            result = int.from_bytes(data, byteorder='little', signed=False)
                        elif instruction_name == 'lhu':
                            address = rs1_value + imm
                            data = self.read_memory(address, 2)
                            result = int.from_bytes(data, byteorder='little', signed=False)
                        elif instruction_name == 'lh':
                            address = rs1_value + imm
                            data = self.read_memory(address, 2)
                            result = int.from_bytes(data, byteorder='little', signed=True)
                        elif instruction_name == 'lb':
                            address = rs1_value + imm
                            data = self.read_memory(address, 1)
                            result = int.from_bytes(data, byteorder='little', signed=True)
                        print(f"Load Result: {result}")
            
            elif instr_type == 'btype':
                rs1 = int(instruction[20:25], 2)
                rs2 = int(instruction[7:12], 2)
                rs1_value = self.registers.get(rs1, 0)
                rs2_value = self.registers.get(rs2, 0)
                imm = int(
                    instruction[0] + instruction[24] +
                    instruction[1:7] + instruction[20:24] + '0', 2)

                if operation:
                    if instruction_name == 'beq':
                        if operation(rs1_value, rs2_value):
                            pc = self.registers.get(32, 0)
                            target_address = pc + imm
                            self.registers[32] = target_address
                    elif instruction_name == 'bne':
                        if not operation(rs1_value, rs2_value):
                            pc = self.registers.get(32, 0)
                            target_address = pc + imm
                            self.registers[32] = target_address
                    elif instruction_name == 'blt':
                        if rs1_value < rs2_value:
                            pc = self.registers.get(32, 0)
                            target_address = pc + imm
                            self.registers[32] = target_address
                    elif instruction_name == 'bge':
                        if rs1_value >= rs2_value:
                            pc = self.registers.get(32, 0)
                            target_address = pc + imm
                            self.registers[32] = target_address
                    elif instruction_name == 'bltu':
                        if rs1_value < rs2_value:
                            pc = self.registers.get(32, 0)
                            target_address = pc + imm
                            self.registers[32] = target_address
                    elif instruction_name == 'bgeu':
                        if rs1_value >= rs2_value:
                            pc = self.registers.get(32, 0)
                            target_address = pc + imm
                            self.registers[32] = target_address

            elif instr_type == 'jtype':
                if instruction_name == 'j':
                    imm = int(instruction[0] + instruction[12:20] + instruction[11] +
                               instruction[1:11] + instruction[20] + instruction[21:31] + '0', 2)
                    target_address = (pc & 0xF0000000) | (imm << 1)
                    self.registers[32] = target_address
                elif instruction_name == 'jal':
                    imm = int(instruction[0] + instruction[12:20] + instruction[11] +
                               instruction[1:11] + instruction[20] + instruction[21:31] + '0', 2)
                    target_address = (pc & 0xF0000000) | (imm << 1)
                    self.registers[32] = target_address | 0x1

            elif instr_type == 'ujtype':
                if instruction_name == 'jal':
                    imm = int(instruction[0] + instruction[21] + instruction[1:11] +
                               instruction[11] + instruction[12:20] + '0', 2)
                    target_address = (pc & 0xF0000000) | (imm << 1)
                    self.registers[32] = target_address | 0x1

            elif instr_type == 'utype':
                if instruction_name == 'lui':
                    imm = int(instruction[0:20], 2)
                    rd = int(instruction[20:25], 2)
                    self.registers[rd] = imm
           
            elif instr_type == 'itype' and instruction_name == 'jalr':
                rs1 = int(instruction[20:25], 2)
                rs1_value = self.registers.get(rs1, 0)
                imm = int(instruction[0:12], 2)
                if imm & 0x800:
                    imm |= 0xFFFFF000  
                target_address = (rs1_value + imm) & 0xFFFFFFFE  
                self.registers[32] = target_address | 0x1

    #def print_memory(self):
        #for address, value in sorted(self.memory.items()):
            #print(f"Address: 0x{address:08x}, Value: 0x{value:02x}")

    def process_elf_file(self, elf_file_path):
        pc = 0
        if not os.path.exists(elf_file_path):
            print(f"Error: ELF file '{elf_file_path}' not found.")
            return

        text_section_data = b""
        with open(elf_file_path, "rb") as file:
            elffile = ELFFile(file)
            for section in elffile.iter_sections():
                if section.name == '.text':
                    text_section_data = section.data()
                if section['sh_flags'] & 0x4:
                    section_data = section.data()
                    md = Cs(CS_ARCH_RISCV, CS_MODE_32)
                    for instr in md.disasm(section_data, section['sh_addr']):
                        address = instr.address
                        instruction_bytes = instr.bytes
                        self.write_memory(address, instruction_bytes)
                        instruction = ''.join(f"{byte:08b}" for byte in instruction_bytes)
                        self.perform_instruction(instruction)

def main():
    downloads_dir = os.path.expanduser('~/Downloads')
    elf_file_path = os.path.join(downloads_dir, 'sting.elf')

    elf_processor = ElfFileProcessor()
    elf_processor.process_elf_file(elf_file_path)
    #elf_processor.print_memory()

if __name__ == "__main__":
    main()



#from elftools.elf.elffile import ELFFile
#import os
#import subprocess
#
#class Memory:
    #def __init__(self):
        #self.memory = {}
#
    #def read_memory(self, address, size):
        #data = b""
        #for i in range(size):
            #data += bytes([self.memory.get(address + i, 0)])
        #return data
    #
    #def write_memory(self, address, data):
        #for i, byte in enumerate(data):
            #self.memory[address + i] = byte
#
    #def print_memory(self):
        #for address, value in sorted(self.memory.items()):
            #print(f"Address: 0x{address:08x}, Value: 0x{value:02x}")
#
#def extract_instructions_from_objdump(elf_file_path):
    #objdump_cmd = f"riscv64-unknown-elf-objdump -d {elf_file_path}"
    #objdump_output = subprocess.check_output(objdump_cmd, shell=True).decode()
#
    #memory = Memory()
#
    #for line in objdump_output.split('\n'):
        #parts = line.strip().split()
        #if len(parts) >= 2 and parts[0].startswith("0x"):
            #address = int(parts[0], 16)
            #instruction = " ".join(parts[1:])
            #memory.write_memory(address, bytes.fromhex(instruction.replace(" ", "")))
#
    #return memory

#def extract_address_and_opcode_from_objdump(elf_file_path):
    #objdump_cmd = f"riscv64-unknown-elf-objdump -d {elf_file_path}"
    #objdump_output = subprocess.check_output(objdump_cmd, shell=True).decode()
#
    #address_opcode_list = []
#
    #for line in objdump_output.split('\n'):
        #parts = line.strip().split()
        #if len(parts) >= 2 and parts[0].startswith("0x"):
            #address = int(parts[0], 16)
            #opcode = " ".join(parts[1:])
            #address_opcode_list.append((address, opcode))
#
    #return address_opcode_list
#
#def main():
    #downloads_dir = os.path.expanduser('~/Downloads')
    #elf_file_path = os.path.join(downloads_dir, 'sting.elf')
    #with open(elf_file_path, "rb") as file:
        #elffile = ELFFile(file)
#
        #address_opcode_list = extract_address_and_opcode_from_objdump(elf_file_path)
#
        #for address, opcode in address_opcode_list:
            #print(f"Address: 0x{address:08x}, Opcode: {opcode}")
#
#if __name__ == "__main__":
    #main()


