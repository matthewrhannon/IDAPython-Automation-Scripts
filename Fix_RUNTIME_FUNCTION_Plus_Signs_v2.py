import idaapi
import ida_bytes
import ida_ua
import ida_funcs

# Size of a RUNTIME_FUNCTION structure in bytes (3 DWORDs)
RUNTIME_FUNCTION_SIZE = 12  # 3 * 4 bytes

# Function to calculate the absolute address by adding base and offset
def calculate_address(base_addr, offset):
    return base_addr + offset

# Function to handle disassembly lines with a '+' character
def parse_disasm_for_addition(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea):
        # Iterate over the operands of the instruction (no need for UA_MAXOP)
        for i in range(len(insn.ops)):
            operand = insn.ops[i]
            # Only process immediate type operands that might involve an addition
            if operand.type == ida_ua.o_imm:
                operand_str = ida_ua.print_operand(insn.ea, i)
                if '+' in operand_str:
                    try:
                        # Attempt to split the operand string and parse the base and offset
                        parts = operand_str.split('+')
                        base_addr = int(parts[0].strip(), 16)
                        offset = int(parts[1].strip(), 16)
                        return base_addr + offset
                    except Exception as e:
                        print(f"Failed to parse operand {operand_str}: {e}")
                        return None
    return None

# Parse a RUNTIME_FUNCTION structure from memory at a given address
def parse_runtime_function(ea):
    try:
        begin_address = ida_bytes.get_dword(ea)
        end_address = ida_bytes.get_dword(ea + 4)
        unwind_info_address = ida_bytes.get_dword(ea + 8)
        return begin_address, end_address, unwind_info_address
    except Exception as e:
        print(f"Failed to parse RUNTIME_FUNCTION at {hex(ea)}: {e}")
        return None, None, None

# Function to process and create a single function for a given address range
def create_function(begin_ea, end_ea):
    print(f"Creating function from {hex(begin_ea)} to {hex(end_ea)}")

    # If a function already exists at the address, delete it
    existing_func = ida_funcs.get_func(begin_ea)
    if existing_func:
        print(f"Deleting existing function at {hex(begin_ea)}")
        ida_funcs.del_func(begin_ea)
    
    # Undefine existing items in the address range
    print(f"Undefining items from {hex(begin_ea)} to {hex(end_ea)}")
    ida_bytes.del_items(begin_ea, ida_bytes.DELIT_SIMPLE, end_ea - begin_ea)  # Remove existing items

    # Attempt to define a new function at this address range
    if not ida_funcs.add_func(begin_ea, end_ea):
        print(f"Failed to define function from {hex(begin_ea)} to {hex(end_ea)}")
    else:
        print(f"Successfully defined function from {hex(begin_ea)} to {hex(end_ea)}")

# Main function to process consecutive RUNTIME_FUNCTION entries and handle disassembly lines
def find_and_process_runtime_functions(start_ea, end_ea, image_base):
    print(f"Scanning from {hex(start_ea)} to {hex(end_ea)} for RUNTIME_FUNCTION entries...")

    current_func_begin = None
    current_func_end = None

    ea = start_ea
    while ea < end_ea:
        # Parse the current RUNTIME_FUNCTION entry
        begin_address, end_address, unwind_info_address = parse_runtime_function(ea)

        # Skip invalid RUNTIME_FUNCTION entries
        if begin_address is None or end_address is None:
            print(f"Skipping invalid RUNTIME_FUNCTION entry at {hex(ea)}")
            ea += RUNTIME_FUNCTION_SIZE
            continue

        # Convert relative addresses to absolute addresses
        begin_ea = calculate_address(image_base, begin_address)
        end_ea_real = calculate_address(image_base, end_address)

        # Get the disassembly line at this address to check for a '+'
        disasm_ea = parse_disasm_for_addition(begin_ea)
        if disasm_ea:
            print(f"Found '+' character in disassembly at {hex(begin_ea)}: adjusted to {hex(disasm_ea)}")
            begin_ea = disasm_ea

        # Check if this RUNTIME_FUNCTION is consecutive to the current one
        if current_func_end is None:
            # First RUNTIME_FUNCTION entry or starting new range
            current_func_begin = begin_ea
            current_func_end = end_ea_real
        elif current_func_end == begin_ea:
            # Extend the current function range
            current_func_end = end_ea_real
        else:
            # Current function range is complete; create a function
            create_function(current_func_begin, current_func_end)

            # Start new function range
            current_func_begin = begin_ea
            current_func_end = end_ea_real

        # Move to the next RUNTIME_FUNCTION entry
        ea += RUNTIME_FUNCTION_SIZE

    # After the loop, create the final function if any range remains
    if current_func_begin is not None and current_func_end is not None:
        create_function(current_func_begin, current_func_end)

# Example usage: Replace these with actual start and end effective addresses
start_ea = 0x147BC2000  # Example start address
end_ea = 0x147EB24A8    # Example end address
image_base = 0x140000000  # Example image base (can be retrieved from the binary)

# Scan and process RUNTIME_FUNCTION entries
find_and_process_runtime_functions(start_ea, end_ea, image_base)
