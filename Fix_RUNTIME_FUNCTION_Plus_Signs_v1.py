import idaapi
import idc
import idautils

# Size of a RUNTIME_FUNCTION structure in bytes (3 DWORDs)
RUNTIME_FUNCTION_SIZE = 12  # 3 * 4 bytes

# Function to calculate the absolute address by adding base and offset
def calculate_address(base_addr, offset):
    return base_addr + offset

# Parse a RUNTIME_FUNCTION structure from memory at a given address
def parse_runtime_function(ea):
    begin_address = idc.get_wide_dword(ea)
    end_address = idc.get_wide_dword(ea + 4)
    unwind_info_address = idc.get_wide_dword(ea + 8)
    return begin_address, end_address, unwind_info_address

# Process a RUNTIME_FUNCTION entry
def process_runtime_function_entry(ea, image_base):
    begin_address, end_address, unwind_info_address = parse_runtime_function(ea)

    # Convert relative addresses to absolute addresses
    begin_ea = calculate_address(image_base, begin_address)
    end_ea = calculate_address(image_base, end_address)

    print(f"RUNTIME_FUNCTION at {hex(ea)}:")
    print(f"  Begin Address: {hex(begin_ea)}")
    print(f"  End Address: {hex(end_ea)}")
    print(f"  Unwind Info Address: {hex(calculate_address(image_base, unwind_info_address))}")

    # Now we can process the calculated addresses, e.g., delete, undefine, redefine functions
    process_address(begin_ea)

# Function to undefine and create a new function at the given address
def process_address(new_ea):
    print(f"Processing address: {hex(new_ea)}")
    
    # If a function exists at this address, delete it
    existing_func = idaapi.get_func(new_ea)
    if existing_func:
        print(f"Deleting function at {hex(new_ea)}")
        idaapi.del_func(new_ea)
    
    # Try undefining the bytes at this address
    print(f"Undefining code at {hex(new_ea)}")
    idaapi.auto_make_code(new_ea)  # Mark as code for analysis
    idc.del_items(new_ea, idc.DELIT_SIMPLE)  # Remove existing items (code or data)
    
    # Attempt to define a new function at this address
    if not idaapi.add_func(new_ea):
        print(f"Failed to define function at {hex(new_ea)}")
    else:
        print(f"Successfully defined function at {hex(new_ea)}")

# Main function to iterate over a range and find RUNTIME_FUNCTION entries
def find_and_process_runtime_functions(start_ea, end_ea, image_base):
    print(f"Scanning from {hex(start_ea)} to {hex(end_ea)} for RUNTIME_FUNCTION entries...")

    ea = start_ea
    while ea < end_ea:
        # Parse each RUNTIME_FUNCTION entry (each is 12 bytes in size)
        process_runtime_function_entry(ea, image_base)
        ea += RUNTIME_FUNCTION_SIZE

# Example usage: Replace these with actual start and end effective addresses
start_ea = 0x147BC2000  # Example start address
end_ea = 0x147EB24A8    # Example end address
image_base = 0x140000000  # Example image base (can be retrieved from the binary)

# Scan and process RUNTIME_FUNCTION entries
find_and_process_runtime_functions(start_ea, end_ea, image_base)
