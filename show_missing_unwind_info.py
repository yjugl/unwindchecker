from bitmap import BitMap
from capstone import *
from pefile import PE

from binascii import hexlify
import sys

IMAGE_SCN_MEM_EXECUTE = 0x20000000

md = Cs(CS_ARCH_X86, CS_MODE_64)

def sequences_of_zeros(bitmap):
    size = bitmap.size()
    start = 0
    end = 0
    while start < size:
        while start < size and bitmap[start]:
            start += 1
        end = start + 1
        while end < size and not bitmap[end]:
            end += 1
        yield (start, end - start)
        start = end + 1

def to_string(i):
    return "0x%x:\t%s\t%s\t%s" %(i.address, hexlify(i.bytes).decode("ascii"), i.mnemonic, i.op_str)

def show_missing_unwind_info_in_section(pe, section):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    section_name = section.Name.rstrip(b"\0").decode("ascii")
    section_bitmap = BitMap(section.section_max_addr - section.section_min_addr)

    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        if entry.struct.BeginAddress >= section.section_min_addr and entry.struct.EndAddress <= section.section_max_addr:
            for addr in range(entry.struct.BeginAddress, entry.struct.EndAddress):
                section_bitmap.set(addr - section.section_min_addr)

    print("Section {}: unwind information covers {:.2f}% of {} bytes.".format(section_name, 100 * (section_bitmap.count() / section_bitmap.size()), section_bitmap.size()))
    print()
    print("Looking for call instructions in the parts not covered by unwind information...")
    print()

    count = 0
    for (uncovered_start, uncovered_size) in sequences_of_zeros(section_bitmap):
        if uncovered_size >= 5:
            code = pe.get_data(section.section_min_addr + uncovered_start, uncovered_size)
            code_start = image_base + section.section_min_addr + uncovered_start
            next_instructions_to_print = 0
            current_call = None
            for i in md.disasm(code, code_start):
                if i.mnemonic == "call":
                    current_call = i
                    next_instructions_to_print = 3
                elif next_instructions_to_print > 0:
                    if current_call is not None:
                        count += 1
                        print(to_string(current_call))
                        current_call = None
                    print(to_string(i))
                    if i.mnemonic == "jmp":
                        next_instructions_to_print = 0
                    else:
                        next_instructions_to_print -= 1
                    if next_instructions_to_print == 0:
                        print()
    if count > 0:
        print("Found {} call instructions without unwind information in section {}.".format(count, section_name))
        print("Note that some of those may be false positives.")
    else:
        print("Found no call instructions without unwind information in section {}.".format(section_name))
    print()

def show_missing_unwind_info(pe):
    for section in pe.sections:
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            show_missing_unwind_info_in_section(pe, section)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python {} <EXE or DLL file> [<EXE or DLL file> ...]".format(sys.argv[0]))
    for target in sys.argv[1:]:
        print("Loading '{}', please wait...".format(target))
        pe = PE(target)
        print()
        show_missing_unwind_info(pe)
        print()
        print()
