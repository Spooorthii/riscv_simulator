import sys
import random
import array
from elftools.elf.elffile import ELFFile
import os
import re
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_64


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
    imm_int = int(imm1 + imm2, 2)
    if imm_int >= 2048:
        imm_int -= 4096
    return opcode, fun, rs1, rs2, imm_int


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
    memory_address = (reg_val[rs1] + imm) % 2000
    memory_values[memory_address] = reg_val[rs2]


def store_half_memory(rs1, imm, rs2):
    memory_address = (reg_val[rs1] + imm) % 2000
    original_value = memory_values[memory_address]
    reg_val[rs2] = (original_value & 0xFFFF0000) | (reg_val[rs2] & 0xFFFF)
    memory_values[memory_address] = reg_val[rs2]


def load_word_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm) % 2000
    reg_val[rd] = int(memory_values[memory_address])


def load_byite_unsigned_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm) % 2000
    reg_val[rd] = int(memory_values[memory_address] & 0xFF)


def load_half_unsigned_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm) % 2000
    reg_val[rd] = int(memory_values[memory_address] & 0xFFFF)


def load_half_signed_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm) % 2000
    original_value = memory_values[memory_address]
    sign_bit = original_value & 0x8000
    if sign_bit != 0:
        reg_val[rd] = int(original_value | 0xFFFF0000)
    else:
        reg_val[rd] = int(original_value & 0xFFFF)


def load_byte_signed_memory(rs1, imm, rd):
    memory_address = (reg_val[rs1] + imm) % 2000
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
    pc = 0
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

    downloads_dir = os.path.expanduser('~/Downloads')
    elf_file_path = os.path.join(downloads_dir, 'sting.elf')
    pattern = b'<(.*?)>'

    with open(elf_file_path, "rb") as file:
        elffile = ELFFile(file)
        for section in elffile.iter_sections():
            section_name = section.name
            section_data = section.data()
        
        # Check if this section contains executable code
            if section['sh_flags'] & 0x4:
                print(f'Section Name: {section_name}')
            
            # Create a disassembler object for RISC-V 32-bit instructions
                md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
            
            # Disassemble and print each instruction in the section
                address = section['sh_addr']
                for instruction in md.disasm(section_data, address):
                    opcode = instruction.mnemonic
                    address = instruction.address
                    print(f'Address: 0x{address:08X}, Opcode: {opcode}')
    
       #with open(elf_file_path, "rb") as file:
        #elffile = ELFFile(file)
        #for line in file:
        #    line = line.decode('utf-8', errors='ignore')
        #    match = re.search(pattern, line.encode('utf-8'))
        #    if match:
        #        instruction_name = match.group(1).decode('utf-8', errors='ignore')  
        #        print(instruction_name)       

        #for section in elffile.iter_sections():
            #section_name = section.name
            #print(f'Section Name: {section_name}')
            #if section_name == "SEC_mac_0_1":
                #code = elffile.get_section_by_name(section_name)
                #ops  = code.data()
                #addr = code['sh_addr']
                #print(ops)
                #print(f'0x{addr}:\t{ops}')

            #section_data = section.data()
            #section_text = section_data.decode('utf-8', errors='ignore')
            #print(section_data)
            #print(section_text)
            #instructions_to_check = ['addi', 'and', 'slti', 'xori', 'sltu', 'srli', 'xor', 'slliw',
            #                    'add', 'slli', 'sltiu', 'slt', 'sub', 'sll', 'srai', 'srlw',
            #                    'andi', 'ori', 'addiw', 'addw', 'sllw', 'srliw', 'sraiw', 'sra',
            #                    'subw', 'lw', 'lbu', 'lhu', 'lh', 'lb', 'sw', 'sh', 'srl']

            #opcode = None
            #fun = None
            #if any(instr in section_text for instr in instructions_to_check):
            ## You should have definitions for extract_opcode and decode_opcode functions here.
            #    opcode = extract_opcode(section_text)

            #    
            #    opcode = bin(int(extract_opcode(section_text), 16))
            #    print('type  opcode', (opcode))
            #    opcode, rd, fun, rs1, rs2, imm = decode_opcode(section_text)
            #else:
            #    pc += len(section_data)  # You need to define pc variable
            #    key = (opcode, fun)
            #    if key in instruction_mappings:
            #        instruction_name, inst_type, inst_kind, char_oper, operation = instruction_mappings[key]
            #        if imm is not None:
            #            operands = f"{rd}, {rs1}, {imm}"
            #        elif rd is not None:
            #            operands = f"{rd}, {rs1}, {rs2}"
            #        else:
            #            operands = f"{rs2}, {rs1}, {imm}"

            #        if inst_type == 'itype' and inst_kind == 'alu':
            #            result = operation(reg_val[rs1], imm)
            #            reg_val[rd] = result
            #            operands_str = f"{instruction_name} {operands}"
            #            result_str = f"{rd} = {rs1}:{reg_val[rs1]} {char_oper} {imm}"
            #            print(operands_str)
            #            print(result_str)
            #            print(f"{rd}:{result}")
            #        elif inst_type == 'rtype' and inst_kind == 'alu':
            #            result = operation(reg_val[rs1], reg_val[rs2])
            #            reg_val[rd] = result
            #            operands_str = f"{instruction_name} {operands}"
            #            result_str = f"{rd} = {rs1}:{reg_val[rs1]} {char_oper}  {rs2}:{reg_val[rs2]}"
            #            print(operands_str)
            #            print(result_str)
            #            print(f"{rd}:{result}")
            #        elif inst_type == 'itype' and inst_kind == 'lsu':
            #            result = operation(rs1, imm, rd)
            #            operands_str = f"{instruction_name} {rd},{imm}({rs1})"
            #            rs1_str = f"{rs1}:{reg_val[rs1]}"
            #            memory = reg_val[rs1] + imm % 2000
            #            print(operands_str)
            #            print(f"{rs1}:{rs1_str} mem:{memory}")
            #            rd_str = f"{rd}: {reg_val[rd]}"
            #            print(rd_str)
            #        elif inst_type == 'stype' and inst_kind == 'lsu':
            #            result = operation(rs1, imm, rs2)
            #            operands_str = f"{instruction_name} {rs2},{imm}({(rs1)})"
            #            rs1_str = f"{rs1}:{reg_val[rs1]}"
            #            memory = reg_val[rs1] + imm % 2000
            #            print(operands_str)
            #            print(f"{rs1}:{rs1_str} mem:{memory}")
            #            rs2_str = f"{rs2}: {reg_val[rs2]}"
            #            print(rs2_str)
            #        print("\n\n")


if __name__ == "__main__":
    main()


from sim import Memory

# Define opcode values for R-type and I-type instructions
RTYPE_OPCODE = 0x33  # Replace with the actual opcode for R-type instructions
ITYPE_OPCODE = 0x13  # Replace with the actual opcode for I-type instructions

# Function to fetch the next instruction from memory
def fetch_instruction(memory, pc):
    return memory.read_memory(pc, 4)  # Assuming instruction size is 4 bytes

# Function to decode an R-type instruction
def decode_rtype_instruction(instruction):
    # Implement your R-type instruction decoding logic here
    # Example: Extract fields like opcode, source registers, immediate, etc.
    pass

# Function to decode an I-type instruction
def decode_itype_instruction(instruction):
    # Implement your I-type instruction decoding logic here
    # Example: Extract fields like opcode, source register, immediate, etc.
    pass

# Function to simulate an R-type instruction
def simulate_rtype_instruction(decoded_instruction):
    # Implement your R-type instruction simulation logic here
    # Example: Execute ALU operations, update registers, etc.
    pass

# Function to simulate an I-type instruction
def simulate_itype_instruction(decoded_instruction):
    # Implement your I-type instruction simulation logic here
    # Example: Load/store operations, arithmetic operations, etc.
    pass

if __name__ == "__main__":
    # Initialize memory and other necessary components
    memory = Memory()

    # Main instruction simulation loop
    pc = 0x00400000  # Set the initial program counter value

    while True:
        # Fetch the next instruction from memory
        instruction_bytes = fetch_instruction(memory, pc)

        # Decode the instruction based on its type (R or I)
        opcode = (instruction_bytes >> 0) & 0x7F  # Extract opcode bits (adjust as needed)

        if opcode == RTYPE_OPCODE:
            decoded_instruction = decode_rtype_instruction(instruction_bytes)
            # Simulate the R-type instruction
            simulate_rtype_instruction(decoded_instruction)
            pc += 4  # Increment PC by instruction size
        elif opcode == ITYPE_OPCODE:
            decoded_instruction = decode_itype_instruction(instruction_bytes)
            # Simulate the I-type instruction
            simulate_itype_instruction(decoded_instruction)
            pc += 4  # Increment PC by instruction size
        else:
            # Handle other instruction types or termination
            break

    # You can access register values directly from the ELF file as needed

    # Print the final program counter value
    print(f"Program Counter (PC): 0x{pc:08x}")


from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_32

# Define your custom RISC-V emulator
class RiscVEmulator:
    def __init__(self):
        # Initialize CPU state and memory here
        self.registers = [0] * 32
        self.memory = Memory()

    def execute_instruction(self, instruction):
        # Implement instruction execution logic here
        pass

# Your Memory class remains the same
class Memory:
    # ...

def main():
    pc = 0
    downloads_dir = os.path.expanduser('~/Downloads')
    elf_file_path = os.path.join(downloads_dir, 'sting.elf')

    # Initialize the RISC-V emulator
    emulator = RiscVEmulator()

    with open(elf_file_path, "rb") as file:
        elffile = ELFFile(file)
        for section in elffile.iter_sections():
            if section.name == '.text':
                text_section_data = section.data()
                md = Cs(CS_ARCH_RISCV, CS_MODE_32)
                for instr in md.disasm(text_section_data, section['sh_addr']):
                    # Execute each instruction using your custom emulator
                    emulator.execute_instruction(instr)

if __name__ == "__main__":
    main()

# Import necessary libraries
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_32

# Define the Memory class
class Memory:
    def __init__(self):
        self.memory = {}

    def read_memory(self, address, size):
        data = b""
        for i in range(size):
            data += bytes([self.memory.get(address + i, 0)])
        return data

    def write_memory(self, address, data):
        for i, byte in enumerate(data):
            self.memory[address + i] = byte

    def print_memory(self):
        for address, value in sorted(self.memory.items()):
            print(f"Address: 0x{address:08x}, Value: 0x{value:02x}")

# Define a function to load ELF file sections into memory
def load_elf_file_into_memory(file_path, memory):
    with open(file_path, "rb") as file:
        elffile = ELFFile(file)
        for section in elffile.iter_sections():
            if section.name == '.text':
                text_section_data = section.data()
            if section['sh_flags'] & 0x4:
                section_data = section.data()
                md = Cs(CS_ARCH_RISCV, CS_MODE_32)
                for instr in md.disasm(section_data, section['sh_addr']):
                    address = instr.address
                    instruction_name = instr.mnemonic
                    oparand = instr.op_str
                    memory.write_memory(address, instr.bytes)
                    print(f"Address: 0x{address:08x}, Oparand: {oparand}, Name: {instruction_name}")

# Define a function to initialize memory and load ELF file
def initialize_memory(elf_file_path):
    memory = Memory()
    load_elf_file_into_memory(elf_file_path, memory)
    return memory

if __name__ == "__main__":
    # Main logic for memory management
    downloads_dir = os.path.expanduser('~/Downloads')
    elf_file_path = os.path.join(downloads_dir, 'sting.elf')
    memory = initialize_memory(elf_file_path)
    memory.print_memory()

