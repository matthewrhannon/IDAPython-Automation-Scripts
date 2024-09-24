import ida_bytes
import ida_auto
import ida_funcs
import ida_ua
import ida_segment

def reanalyze_function(ea):
    # Get the function object at the given address
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"No function found at address {hex(ea)}")
        return
    
    # Ensure that the function is in an executable segment
    seg = ida_segment.getseg(func.start_ea)
    if not seg or not seg.perm & ida_segment.SEGPERM_EXEC:
        print(f"Segment at {hex(func.start_ea)} is not executable.")
        return
    
    print(f"Forcefully reanalyzing the function at {hex(func.start_ea)}")

    # Undefine all existing code and data in the function's range
    current_ea = func.start_ea
    while current_ea < func.end_ea:
        # Undefine any existing code or data
        ida_bytes.del_items(current_ea, ida_bytes.DELIT_SIMPLE)
        current_ea += 1

    print(f"Undefinition complete, starting reanalysis...")

    # Reset current_ea to the start of the function for reanalysis
    current_ea = func.start_ea
    insn = ida_ua.insn_t()  # Create an insn_t structure for decoding

    while current_ea < func.end_ea:
        # Try to make code at the current address
        if ida_ua.create_insn(current_ea):
            print(f"Created instruction at {hex(current_ea)}")
            current_ea += insn.size  # Advance by the instruction's size
        else:
            print(f"Failed to create instruction at {hex(current_ea)}, moving to the next byte")
            current_ea += 1  # Move to the next byte if decoding fails

    # Mark the function for full reanalysis
    ida_auto.auto_make_code(func.start_ea)
    ida_auto.auto_wait()

    print(f"Reanalysis of the function at {hex(func.start_ea)} completed.")

# Example usage: Pass the effective address (ea) of the function you want to reanalyze
ea = ida_kernwin.get_screen_ea()  # or use any specific address
reanalyze_function(ea)
