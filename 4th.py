from ida_bytes import *
from ida_funcs import *
from ida_idaapi import * # Updated import
from ida_kernwin import *
from ida_search import *
from ida_ua import *
from ida_xref import *
from idc import *

# Adjusted functions to use ida_ida for database limits
from ida_kernwin import *
from idaapi import *
from ida_ida import *

def ask_for_address(prompt, default_value):
    """
    Custom function to ask the user for an address. It handles hexadecimal input robustly.
    """
    # Providing a default string in the expected hexadecimal format
    default_str = "0x%X" % default_value
    # Asking the user for the input, showing the default string
    addr_str = ida_kernwin.ask_str(default_str, ida_kernwin.HIST_IDENT, prompt)
    if addr_str:
        try:
            # Normalize the input by removing '0x' if present and converting to integer
            addr = int(addr_str, 16)
            return addr
        except ValueError:
            # Inform the user of the incorrect input format
            ida_kernwin.warning("Invalid address format. Please enter a valid hexadecimal address.")
            return None
    else:
        # Return the default value if the user cancels the input dialog
        return default_value

def is_instruction(ea):
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def is_data(ea):
    return ida_bytes.is_data(ida_bytes.get_full_flags(ea))

def handle_ref(ref_addr, insn_start_addr, interactive=False):
    if ref_addr > insn_start_addr and is_instruction(ref_addr):
        if interactive and not confirm_action(f"Fix reference at 0x{ref_addr:X}?"):
            print(f"Skipped fixing reference at 0x{ref_addr:X} by user choice.")
            return
        if ida_bytes.create_insn(insn_start_addr):
            print(f"Created new instruction at 0x{insn_start_addr:X}", to_file=True)
        else:
            print(f"Failed to create instruction at 0x{insn_start_addr:X}.", to_file=True)

def find_and_fix_bad_refs(start_addr=None, end_addr=None, interactive=False):
    #ida_kernwin.show_wait_box("Fixing bad memory references...")
    start_addr = start_addr if start_addr else ida_ida.inf_get_min_ea()
    end_addr = end_addr if end_addr else ida_ida.inf_get_max_ea()
    current_addr = start_addr

    try:
        while current_addr < end_addr and current_addr != ida_idaapi.BADADDR:
            current_addr = ida_search.find_code(current_addr, ida_search.SEARCH_DOWN)
            if not is_instruction(current_addr):
                current_addr += 1
                continue

            refs = ida_xref.get_first_dref_to(current_addr)
            while refs != ida_idaapi.BADADDR:
                handle_ref(refs, current_addr, interactive=interactive)
                refs = ida_xref.get_next_dref_to(current_addr, refs)

            current_addr += 1
    finally:
        ida_kernwin.hide_wait_box()

#interactive_mode = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Run in interactive mode?") == ida_kernwin.ASKBTN_YES
#start_range = ask_for_address("Enter start address:", ida_idaapi.inf_get_min_ea())
#end_range = ask_for_address("Enter end address:", ida_idaapi.inf_get_max_ea())

#if start_range is not None and end_range is not None:
#    find_and_fix_bad_refs(start_range, end_range, interactive=interactive_mode)

# Example usage within the script context
interactive_mode = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Run in interactive mode?") == ida_kernwin.ASKBTN_YES

# Use IDA's API to get the current minimum and maximum addresses for asking ranges
start_range = 140695896481648 #0x7FF650EE5F70 #ask_for_address("Enter start address:", ida_ida.inf_get_min_ea())
end_range = 140695896482768 #0x7FF650EE63D0 #ask_for_address("Enter end address:", ida_ida.inf_get_max_ea())

if start_range is not None and end_range is not None:
    print("Selected range: 0x%X - 0x%X" % (start_range, end_range))
    # Here you would call find_and_fix_bad_refs or your intended function
    find_and_fix_bad_refs(start_range, end_range, interactive=interactive_mode)
else:
    print("Invalid range or operation cancelled.")