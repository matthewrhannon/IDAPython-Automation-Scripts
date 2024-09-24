#Clean up non-functions such as stuff between .pdata entries and the next functiion. 8/30/2024

import os
import sys
#sys.path.append(os.path.dirname(os.path.realpath(__file__)))

try:
    from ida_idaapi import idaapi
    print("Got ida_idaapi...")
except:
    import idaapi
    print("Got idaapi...")
    pass

import idc
import ida_bytes
import ida_funcs
import idautils
import ida_search
import idaapi
import idc
import ida_bytes
import ida_funcs
import idautils
import ida_idaapi
import ida_ida

# To get the minimum effective address of the database
min_ea = ida_ida.inf_get_min_ea()

# To get the maximum effective address of the database
max_ea = ida_ida.inf_get_max_ea()

inf = max_ea #ida_idaapi.get_inf_structure()

# Now you can access min_ea and use it with other functions
string = 'Second' #'?pre_cpp_initialization@@YAXXZ'
addr = idaapi.get_name_ea(min_ea, string)

# If addr is valid, print the result
if addr != idaapi.BADADDR:
    print(f"Address of '{string}': {hex(addr)}")
else:
    print(f"ERROR: Could not find '{string}'")

def get_rva(address_str):
    """Extract the base address and the offset, return their sum."""
    base_str, offset_str = address_str.split('+')
    base_addr = int(base_str, 16)
    offset = int(offset_str, 16)
    return base_addr + offset

def process_function_at_rva(rva):
    """Check if a function exists at the given RVA and is valid."""
    func = ida_funcs.get_func(rva)
    if func:
        # Check if the function has multiple cross-references
        if len(list(idautils.XrefsTo(rva))) > 1:
            return True
        else:
            # Check for cross-references from .pdata
            xrefs = [xref.frm for xref in idautils.XrefsTo(rva)]
            if any(idc.get_segm_name(xref) == ".pdata" for xref in xrefs):
                return False
            return True
    return False

def undefine_function(ea):
    """Undefine the function and its bytes if the function is invalid."""
    idc.del_func(ea)
    while True:
        flags = idc.get_full_flags(ea)
        if not ida_bytes.is_code(flags):
            break
        idc.del_items(ea, idc.DELIT_SIMPLE)
        ea = idc.next_head(ea)

def create_valid_function(rva):
    """Create a valid function at the given RVA after ensuring no undefined bytes."""
    # Ensure there are no undefined bytes in the function area
    end_ea = idaapi.BADADDR
    for ref in idautils.XrefsFrom(rva):
        if ref.type == idc.fl_F:
            end_ea = ref.to
            break

    if end_ea != idaapi.BADADDR:
        # Ensure all bytes are defined
        ea = rva
        while ea < end_ea:
            if not ida_bytes.is_code(idc.get_full_flags(ea)):
                if not idc.create_insn(ea):
                    print(f"Failed to define instruction at 0x{ea:X}.")
                    return False
            ea = idc.next_head(ea)
        
        if ida_funcs.add_func(rva, end_ea):
            print(f"Successfully created a valid function at 0x{rva:X} - 0x{end_ea:X}")
        else:
            print(f"Failed to create function at 0x{rva:X}.")
    else:
        print(f"Could not determine function boundaries for 0x{rva:X}.")

def process_executable_segments():
    """Process all executable segments to find and handle specific offset patterns."""
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg.perm & idaapi.SEGPERM_EXEC:
            ea = seg.start_ea
            end_ea = seg.end_ea

            while ea < end_ea:
                disasm_line = idc.generate_disasm_line(ea, 0)

                # Identify lines containing '+'
                if '+' in disasm_line:
                    try:
                        base_and_offset = disasm_line.split('dq offset ')[1].strip()
                        rva = get_rva(base_and_offset)
                        if rva % 4 == 0:
                            # Process the function if the address is valid
                            if not process_function_at_rva(rva):
                                print(f"Invalid function at 0x{rva:X}. Cleaning up...")
                                undefine_function(rva)
                                print(f"Attempting to create valid function at 0x{rva:X}.")
                                create_valid_function(rva)
                            else:
                                print(f"Valid function found at 0x{rva:X}.")
                        else:
                            print(f"Skipping address 0x{rva:X} as it does not align to 4-byte boundary.")
                    except Exception as e:
                        print(f"Error processing line {disasm_line}: {e}")
                ea = idc.next_head(ea)

def process_executable_segments_within_range(start_ea, end_ea):
    """Process all executable segments within a specified address range."""
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if True: #seg.perm & idaapi.SEGPERM_EXEC:
            # Ensure we only process the specified range within this segment
            seg_start = max(seg.start_ea, start_ea)
            seg_end = min(seg.end_ea, end_ea)

            ea = seg_start
            while ea < seg_end:
                disasm_line = idc.generate_disasm_line(ea, 0)

                # Identify lines containing '+'
                if '+' in disasm_line:
                    try:
                        base_and_offset = disasm_line.split('dq offset ')[1].strip()
                        rva = get_rva(base_and_offset)
                        if rva % 4 == 0:
                            # Process the function if the address is valid
                            if not process_function_at_rva(rva):
                                print(f"Invalid function at 0x{rva:X}. Cleaning up...")
                                undefine_function(rva)
                                print(f"Attempting to create valid function at 0x{rva:X}.")
                                create_valid_function(rva)
                            else:
                                print(f"Valid function found at 0x{rva:X}.")
                        else:
                            print(f"Skipping address 0x{rva:X} as it does not align to 4-byte boundary.")
                    except Exception as e:
                        print(f"Error processing line {disasm_line}: {e}")
                ea = idc.next_head(ea)

# For processing within a specific memory range
start_address = 0x142CF68B0 #0x1426612A0 #0x0000000142D05898  # Replace with your desired start address
end_address = 0x147BA35FF #0x14266235F #0x00000001438FCE20    # Replace with your desired end address

def PLUGIN_ENTRY():
    print("Inside PLUGIN_ENTRY function...")
    process_executable_segments_within_range(start_address, end_address)
    
    #Example usage
    #For processing an entire executable segment
    #process_executable_segments()

    

    