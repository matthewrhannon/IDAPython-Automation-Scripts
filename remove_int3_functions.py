import idc
import ida_funcs
import ida_bytes
import idautils

counter = 0
def is_int3_instruction(ea):
    """Check if the instruction at ea is an int3 (0xCC)"""
    return idc.get_wide_byte(ea) == 0xCC

def process_function(func_ea):
    """Process a function to check if it only contains int3 instructions, and undefine if true"""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return
    
    start_ea = func.start_ea
    end_ea = func.end_ea
    current_ea = start_ea

    only_int3 = True

    while current_ea < end_ea:
        if not is_int3_instruction(current_ea):
            only_int3 = False
            break
        current_ea = idc.next_head(current_ea, end_ea)

    if only_int3:
        print(f"Function at 0x{start_ea:X} contains only int3 instructions. Undefining it.")
        ida_funcs.del_func(start_ea)
        idc.del_items(start_ea, idc.DELIT_SIMPLE, end_ea - start_ea)

        # Recreate code without associating with a function
        current_ea = start_ea
        while current_ea < end_ea:
            idc.create_insn(current_ea)
            current_ea = idc.next_head(current_ea, end_ea)
        global counter
        counter = counter + 1

def main():
    for func_ea in idautils.Functions():
        process_function(func_ea)
    global counter
    print("counter=" + str(counter))

if __name__ == "__main__":
    main()
