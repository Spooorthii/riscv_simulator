    Opening and Saving Files:
        vim filename: Open a file in Vim.
        :e filename: Edit another file while keeping the current one open.
        :w: Save changes to the current file.
        :w filename: Save the file with a different name.
        :q: Quit Vim.
        :q!: Quit Vim without saving changes.
        :wq or ZZ: Save changes and quit.

    Navigation:
        h, j, k, l: Move left, down, up, and right, respectively.
        Ctrl + f: Page down.
        Ctrl + b: Page up.
        0 or ^: Move to the beginning of the line.
        $: Move to the end of the line.
        gg: Move to the beginning of the file.
        G: Move to the end of the file.
        :line_number: Move to a specific line number.

    Editing:
        i: Insert before the cursor.
        I: Insert at the beginning of the line.
        a: Append after the cursor.
        A: Append at the end of the line.
        o: Open a new line below the current line.
        O: Open a new line above the current line.
        x: Delete the character under the cursor.
        dd: Delete the current line.
        yy: Copy (yank) the current line.
        p: Paste after the cursor.
        P: Paste before the cursor.
        u: Undo the last change.
        Ctrl + r: Redo.

    Search and Replace:
        /search_term: Search forward for search_term.
        ?search_term: Search backward for search_term.
        n: Move to the next search result.
        N: Move to the previous search result.
        :s/old/new/g: Replace all occurrences of old with new in the entire file.
        :line_number1,line_number2s/old/new/g: Replace in a specific range of lines.

    Copying and Cutting:
        v: Start visual mode for selecting text.
        V: Start visual line mode for selecting lines.
        Ctrl + v: Start visual block mode for selecting rectangular areas.
        y: Yank (copy) selected text.
        d: Delete (cut) selected text.

    Indentation:
        >>: Indent the current line.
        <<: Unindent the current line.
        ==: Auto-indent the current line.
        :set autoindent: Enable auto-indentation.
        :set paste: Paste text without auto-indentation.

    Buffers and Windows:
        :e filename: Open a new file in the current buffer.
        :ls: List all buffers.
        :b buffer_number: Switch to a specific buffer.
        :sp filename: Split the screen horizontally.
        :vsp filename: Split the screen vertically.
        Ctrl + ww: Switch between windows.
        Ctrl + wq: Close the current window.
        Ctrl + wv: Split the screen vertically.

    Miscellaneous:
        :help keyword: Open Vim's built-in help for keyword.
        :q: Quit Vim.
        :q!: Quit Vim without saving changes.
        :wq or ZZ: Save changes and quit.




        #from elftools.elf.elffile import ELFFile
#import os
#from capstone import Cs, CS_ARCH_RISCV, CS_MODE_32  
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
#def main():
    #pc = 0
    #downloads_dir = os.path.expanduser('~/Downloads')
    #elf_file_path = os.path.join(downloads_dir, 'sting.elf')
#
    #memory = Memory()
    #text_section_data = b""  
#
    #with open(elf_file_path, "rb") as file:
        #elffile = ELFFile(file)
        #for section in elffile.iter_sections():
            #if section.name == '.text':
                #text_section_data = section.data()  
            #if section['sh_flags'] & 0x4:
                #section_data = section.data()
                #md = Cs(CS_ARCH_RISCV, CS_MODE_32)
                #for instr in md.disasm(section_data, section['sh_addr']):
                    #address = instr.address
                    #instruction_name = instr.mnemonic
                    #oparand = instr.op_str
                    #memory.write_memory(address, instr.bytes)
#
                    #print(f"Address: 0x{address:08x}, Oparand: {oparand}, Name: {instruction_name}")
#
    #memory.print_memory()
#
#if __name__ == "__main__":
    #main()
#
#

