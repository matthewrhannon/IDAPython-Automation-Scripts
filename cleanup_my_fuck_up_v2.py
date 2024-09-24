import ida_funcs
import idc
import ida_kernwin
import ida_segment

def is_valid_address(ea):
    """
    Checks if the given address is valid in the current IDB (falls within a segment).
    """
    seg = ida_segment.getseg(ea)
    return seg is not None

def process_rvas_from_file(file_path):
    try:
        # Open the file containing RVAs
        with open(file_path, 'r') as file:
            for line in file:
                # Strip any extra whitespace and newlines
                rva = line.strip()
                
                # Check if the line starts with '0x' and is a valid hex number
                if rva.startswith("0x"):
                    try:
                        # Convert the hex string to an address
                        rva_address = int(rva, 16)
                        
                        # Check if the address is valid within IDB
                        if not is_valid_address(rva_address):
                            print(f"Invalid address or not within a valid segment: {rva}")
                            continue

                        # Check if there's a function at this address
                        func = ida_funcs.get_func(rva_address)
                        if func:
                            # Undefine the function
                            if idc.del_func(rva_address):
                                print(f"Successfully undefined function at {rva}")
                            else:
                                print(f"Failed to undefine function at {rva}")
                                #continue
                            
                            # Redefine the function
                            if idc.add_func(rva_address):
                                print(f"Successfully redefined function at {rva}")
                            else:
                                print(f"Failed to redefine function at {rva}")
                        else:
                            print(f"No function found at {rva}")
                            # Redefine the function
                            if idc.add_func(rva_address):
                                print(f"Successfully redefined function at {rva}")
                            else:
                                print(f"Failed to redefine function at {rva}")
                    except ValueError as e:
                        print(f"Invalid hex address: {rva} - {e}")
                else:
                    print(f"Invalid format for RVA: {rva}")
    except Exception as e:
        print(f"Error processing file: {e}")

# Example usage
file_path = ida_kernwin.ask_file(0, "*.txt", "Please select the RVA file")  # Prompt user for file
if file_path:
    process_rvas_from_file(file_path)
