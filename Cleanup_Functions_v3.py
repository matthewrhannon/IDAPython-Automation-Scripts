import idautils
import idaapi
import idc
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import nltk
from nltk.corpus import words
import string

# Ensure the necessary resources are downloaded
nltk.download('words')

# Load the word list
english_words = set(words.words())

# Function to check if a string is a valid word
def is_valid_word(s):
    return s.lower() in english_words

# Function to extract a potential string from memory and check if it is a valid word
def check_memory_for_string(ea, length=100):
    encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32']
    str_types = [idc.STRTYPE_C, ida_nalt.STRTYPE_C_16]
    
    try:
        for str_type in str_types:
            extracted_str = idc.get_strlit_contents(ea, length, str_type)
            if not extracted_str:
                continue

            for encoding in encodings:
                try:
                    decoded_str = extracted_str.decode(encoding).strip(string.punctuation)
                    # Check if the decoded string is a valid word
                    if is_valid_word(decoded_str):
                        print(f"Address {hex(ea)} contains a valid {encoding} word: '{decoded_str}'")
                        return True
                except (UnicodeDecodeError, AttributeError):
                    continue  # If decoding fails or if there's no valid string, continue with the next encoding
    except Exception as e:
        print(f"Error while checking memory at {hex(ea)}: {e}")
    
    return False

# Function to get the number of cross-references to a given address
def count_xrefs(ea):
    return len(list(idautils.XrefsTo(ea)))

# Function to define data at a specific address and return the number of cross-references
def define_data_and_check_xrefs(ea, data_type):
    if data_type == "byte":
        ida_bytes.create_data(ea, idc.FF_BYTE, 1, idaapi.BADADDR)
    elif data_type == "word":
        ida_bytes.create_data(ea, idc.FF_WORD, 2, idaapi.BADADDR)
    elif data_type == "dword":
        ida_bytes.create_data(ea, idc.FF_DWORD, 4, idaapi.BADADDR)
    elif data_type == "qword":
        ida_bytes.create_data(ea, idc.FF_QWORD, 8, idaapi.BADADDR)
    else:
        print("Unsupported data type")
        return -1  # Return -1 to indicate failure

    xrefs_count = count_xrefs(ea)
    print(f"Defined {data_type} at {hex(ea)}, Xrefs: {xrefs_count}")

    #idc.refresh_idaview_anyway();
    #idc.refresh_choosers();
    
    return xrefs_count

# Main function to define data at an undefined address and check cross-references
def define_data_with_xref_and_string_check(ea):
    ea_bak = ea
    
    # Check if the memory at the address contains a valid word in any encoding
    if check_memory_for_string(ea):
        print(f"Skipping data definition at {hex(ea)} due to valid string content.")
        return

    # Attempt to define data if the address is undefined or contains unknown data
    if not ida_bytes.is_loaded(ea) or ida_bytes.is_unknown(ea):
        print(f"Address {hex(ea)} is undefined or contains unknown data. Attempting to define data.")
        original_xrefs = define_data_and_check_xrefs(ea, "byte")
    else:
        original_xrefs = count_xrefs(ea)

    print(f"Original Xrefs at {hex(ea)}: {original_xrefs}")

    data_types = ["word", "dword", "qword"]  # Start with "word" since "byte" was already attempted

    for i in range(len(data_types)):
        # Try to define the current data type
        current_xrefs = define_data_and_check_xrefs(ea, data_types[i])

        # Check if we should stop (xrefs started to increase)
        if current_xrefs > original_xrefs:
            print(f"Stopping at {data_types[i]} due to increased xrefs.")
            break

        # If this is the last type, no need to check further
        if i == len(data_types) - 1:
            if check_memory_for_string(ea_bak):
                print(f"Skipping data definition at {hex(ea)} due to valid string content.")
                return
            break

        # Update the original_xrefs for the next iteration
        original_xrefs = current_xrefs

def undefine_instructions_in_rdata(start_ea, end_ea):
    """Undefine any instructions in the .rdata segment and try to identify valid data."""
    print(f"Undefining instructions in .rdata from 0x{start_ea:X} to 0x{end_ea:X}.")
    ea = start_ea
    while ea < end_ea:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags):
            print(f"Undefining instruction at 0x{ea:X}.")
            idc.del_items(ea, idc.DELIT_SIMPLE)
        ea = idc.next_head(ea)

def define_strings_in_rdata(start_ea, end_ea):
    """Identify and define valid strings in the .rdata section."""
    print(f"Defining strings in .rdata from 0x{start_ea:X} to 0x{end_ea:X}.")
    ea = start_ea
    while ea < end_ea:
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_code(flags) and not ida_bytes.is_data(flags):
            # Attempt to create an ASCII string
            if idc.create_strlit(ea, idc.BADADDR):
                print(f"Created ASCII string at 0x{ea:X}.")
                ea = idc.get_str_end(ea)
            else:
                # Attempt to create a Unicode string
                if idc.create_strlit(ea, idc.BADADDR, ida_nalt.STRTYPE_C_16):
                    print(f"Created Unicode string at 0x{ea:X}.")
                    ea = idc.get_str_end(ea)
                else:
                    ea = idc.next_head(ea)
        else:
            ea = idc.next_head(ea)

def process_rdata_segment():
    """Process the .rdata segment to remove any instructions and define valid data."""
    rdata_seg = None
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and idc.get_segm_name(seg.start_ea) == ".rdata":
            rdata_seg = seg
            break
    
    if not rdata_seg:
        print("No .rdata segment found.")
        return
    
    start_ea = rdata_seg.start_ea
    end_ea = rdata_seg.end_ea
    
    undefine_instructions_in_rdata(start_ea, end_ea)
    define_strings_in_rdata(start_ea, end_ea)

def get_rva(address_str):
    """Extract the base address and the offset, resolve the address, and return their sum if valid."""
    base_str, offset_str = address_str.split('+')

    # Resolve the base_str to an actual address if it's a label
    if not base_str.startswith('0x') and not base_str.isdigit():
        base_addr = idc.get_name_ea_simple(base_str)
        if base_addr == idaapi.BADADDR:
            print(f"get_rva: Could not resolve symbol {base_str} to an address.")
            return None
        else:
            print(f"Resolved symbol {base_str} to address 0x{base_addr:X}.")

            for ref in idautils.CodeRefsTo(base_addr, 1):
                print('0 ' +hex(ref))
                idc.generate_disasm_line(ref,0)
    else:
        try:
            base_addr = int(base_str, 16)
            print(f"Parsed base address: 0x{base_addr:X}")
        except ValueError:
            print(f"Error: Invalid base address {base_str}.")
            return None

    # Strip out any extraneous text after the offset (e.g., "; 2 2 2 2" or "h")
    base_addr = base_str.split(';')[0].strip().rstrip('h').rstrip('H')
    if base_addr == '' or base_addr == None:
        base_addr = int(base_str, 16)
        
    try:
        if len(offset_str) == 0:
            resolved_address = base_addr
            offset = int(resolved_address, 16)
            print(f"Computed RVA: 0x{resolved_address:X}")
            return resolved_address  
        else:  
            offset = int(offset_str, 16)
            print(f"Parsed offset: 0x{offset:X}")
    except ValueError:
        print(f"Error: Invalid offset {offset_str}.")
        return None
    
    resolved_address = base_addr + offset
    print(f"Computed RVA: 0x{resolved_address:X}")
    return resolved_address
    
def get_rva_no_plus(address_str):
    """Extract the base address and no offset, resolve the address, and return their if valid."""
    base_str = address_str

    # Resolve the base_str to an actual address if it's a label
    if not base_str.startswith('0x') and not base_str.isdigit():
        base_addr = idc.get_name_ea_simple(base_str)
        if base_addr == idaapi.BADADDR:
            print(f"get_rva_no_plus: Could not resolve symbol {base_str} to an address.")
            return None
        else:
            print(f"Resolved symbol {base_str} to address 0x{base_addr:X}.")
            for ref in idautils.CodeRefsTo(base_addr, 1):
                print('1  ' + hex(ref))
                idc.generate_disasm_line(ref,0)
    else:
        try:
            base_addr = int(base_str, 16)
            print(f"Parsed base address: 0x{base_addr:X}")
        except ValueError:
            print(f"Error: Invalid base address {base_str}.")
            return None

    # Strip out any extraneous text after the offset (e.g., "; 2 2 2 2" or "h")
    base_addr = base_str.split(';')[0].strip().rstrip('h').rstrip('H')
    if base_addr == '' or base_addr == None:
        base_addr = int(base_str, 16)
        
    resolved_address = base_addr
    print(f"Computed RVA: 0x{resolved_address:}")
    return resolved_address
    
def undefine_area(start_ea, end_ea):
    """Undefine all instructions and data in the specified range."""
    print(f"Undefining area from 0x{start_ea:X} to 0x{end_ea:X}.")
    ea = start_ea
    while ea < end_ea:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags) or ida_bytes.is_data(flags):
            print(f"Undefining item at 0x{ea:X}.")
            idc.del_items(ea, idc.DELIT_SIMPLE)
        ea = idc.next_head(ea)

def undefine_function(ea):
    """Undefine the function and its bytes if the function is invalid."""
    func = ida_funcs.get_func(ea)
    if func:
        print(f"Deleting function at 0x{ea:X}.")
        ida_funcs.del_func(ea)
        undefine_area(func.start_ea, func.end_ea)
    else:
        print(f"No function found at 0x{ea:X} to delete.")

def aggressively_undefine_surrounding_area(ea, range_size=0x10):
    """Undefine the area around the current address, looking upwards and downwards."""
    temp = here()
    pos = idc.goto(ea)
    segshit = idc.here()
    idc.goto(temp)
    
    #seg = idaapi.getseg(ea)
    seg = idaapi.getseg(idaapi.to_ea(segshit))
    if not seg:
        print(f"Error: Unable to find segment for address 0x{ea:X}.")
        return
    
    start_ea = max(ea - range_size, seg.start_ea)
    end_ea = min(ea + range_size, seg.end_ea)
    print(f"Aggressively undefining surrounding area from 0x{start_ea:X} to 0x{end_ea:X}.")
    undefine_area(start_ea, end_ea)

def create_valid_function(rva, end_ea=None):
    """Create a valid function at the given RVA, correcting boundaries if necessary."""
    if end_ea is None:
        # Default to scanning for the end of the function
        end_ea = idaapi.BADADDR
        for ref in idautils.XrefsFrom(rva):
            if ref.type == idc.fl_F and is_within_segment(ref.to):
                end_ea = ref.to
                break
    
    # If end_ea is still BADADDR, assume a default function size
    if end_ea == idaapi.BADADDR or not is_within_segment(end_ea):
        end_ea = rva + 0x10 #0x10  # Adjust this size as needed

    print(f"Attempting to create function at 0x{rva:X} with end at 0x{end_ea:X}.")
    
    # Undefine any existing code or data in the range
    undefine_area(rva, end_ea)
    
    ea = rva
    while ea < end_ea:
        if ida_kernwin.user_cancelled():
            print("Script cancelled by user.")
            return False
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            if not idc.create_insn(ea):
                print(f"Failed to define instruction at 0x{ea:X}. Undefining surrounding area and retrying.")
                aggressively_undefine_surrounding_area(ea)
                if not idc.create_insn(ea):
                    print(f"Failed to define instruction again at 0x{ea:X}. Aborting.")
                    return False
        ea = idc.next_head(ea)
    
    if ida_funcs.add_func(rva, end_ea):
        print(f"Successfully created a valid function at 0x{rva:X} - 0x{end_ea:X}")
    else:
        print(f"Failed to create function at 0x{rva:X}.")

def process_function_at_rva(rva):
    """Check if a function exists at the given RVA and ensure it is valid based on alignment and boundaries."""
    if not is_within_segment(rva):
        print(f"Address 0x{rva:X} is not within a valid segment. Skipping.")
        return False
    
    func = ida_funcs.get_func(rva)
    
    # Ensure the function starts exactly at the given RVA
    if func and func.start_ea == rva:
        return True
    elif func:
        print(f"Function exists but starts at 0x{func.start_ea:X}, expected 0x{rva:X}. Undefining and correcting.")
        undefine_function(func.start_ea)
        create_valid_function(rva)
        return False
    else:
        print(f"No function found at 0x{rva:X}. Creating new function.")
        create_valid_function(rva)
        return True

def process_executable_segments_within_range(start_ea, end_ea):
    """Process all segments within a specified address range."""
    try:
        ida_kernwin.show_wait_box("Processing segments...\n\nPress 'Cancel' to stop the script.")
        
        for seg_ea in idautils.Segments():
            if ida_kernwin.user_cancelled():
                print("Script cancelled by user.")
                break

            seg = idaapi.getseg(seg_ea)
            if seg:
                seg_start = max(seg.start_ea, start_ea)
                seg_end = min(seg.end_ea, end_ea)

                ea = seg_start
                while ea < seg_end:
                    if ida_kernwin.user_cancelled():
                        print("Script cancelled by user.")
                        return

                    disasm_line = idc.generate_disasm_line(ea, 0)

                    if 'dq offset ' in disasm_line and '+' in disasm_line:
                        try:
                            parts = disasm_line.split('dq offset ')
                            if len(parts) > 1 and '+' in parts[1]:
                                base_and_offset = parts[1].strip()
                                rva = get_rva(base_and_offset)
                                if rva is not None:
                                    if not process_function_at_rva(rva):
                                        print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
                                        create_valid_function(rva)
                                    else:
                                        print(f"Valid function processed at 0x{rva:X}.")
                                        
                                        ea = idc.next_head(ea)
                                        if ida_kernwin.user_cancelled():
                                            print("Script cancelled by user.")
                                            return                                        
                                        continue
                                else:
                                    print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")           
                        except Exception as e:
                            print(f"Error processing line '{disasm_line}': {e}")
                    elif 'dq offset ' in disasm_line:
                        parts = disasm_line.split('dq offset ')
                        if len(parts) > 1:
                            base_and_offset = parts[1].strip()
                            rva = get_rva_no_plus(disasm_line.split('dq offset ')[1].strip())
                            if rva != None:
                                if not process_function_at_rva(rva):
                                    print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
                                    create_valid_function(rva)
                                    idc.op_offset(hex(rva), 0, idc.REF_OFF64)
                                else:
                                    print(f"Valid function processed at 0x{rva:X}.")
                                    
                                    # Create a dq (8-byte) offset at the current ea
                                    #idc.op_offset(rva, 0, idc.REF_OFF64)
                                    
                                    #ea = idc.next_head(ea)
                                    if ida_kernwin.user_cancelled():
                                        print("Script cancelled by user.")
                                        return
                                    #continue
                            else:
                                print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")
                    elif 'dq ' in disasm_line:
                        parts = disasm_line.split('dq ')
                        if len(parts) > 1:
                            base_and_offset = parts[1].strip()
                            rva = get_rva_no_plus(disasm_line.split('dq ')[1].strip())  
                            if rva != None:
                                if not process_function_at_rva(rva):
                                    print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
                                    create_valid_function(rva)
                                    idc.op_offset(hex(rva), 0, idc.REF_OFF64)
                                else:
                                    print(f"Valid function processed at 0x{rva:X}.")
                                    
                                    # Create a dq (8-byte) offset at the current ea
                                    #idc.op_offset(rva, 0, idc.REF_OFF64)
                                    
                                    #ea = idc.next_head(ea)
                                    if ida_kernwin.user_cancelled():
                                        print("Script cancelled by user.")
                                        return
                                    #continue
                            else:
                                print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")
                    elif 'dq' in disasm_line:
                        #encodings = ['db', 'ds', 'dw', 'dq']
                        # Handle defining strings (ASCII) in .rdata or any segment
                        string_content = disasm_line.split('db ')[1].strip()
                        
                        ea = idc.get_screen_ea()  # Use the current address in IDA
                        define_data_with_xref_and_string_check(ea)
                    else:
                        print(f"No db found at '{disasm_line}'. Turning to string...")
                        
                        ea = idc.get_screen_ea()  # Use the current address in IDA
                        define_data_with_xref_and_string_check(ea)                        
                        #define_strings_in_rdata(ea, (len(string_content) * 2) + 1)
                        #define_strings_in_rdata(ea, (len(string_content) * 1))
                        
                    ea = idc.next_head(ea)
                    if ida_kernwin.user_cancelled():
                        print("Script cancelled by user.")
                        return
    finally:
        ida_kernwin.hide_wait_box()

print('\n---Starting Cleanup_Functions---\n')

# Process the .rdata segment first to clean it up
#process_rdata_segment()

# Specify the range you want to process in executable segments
start_address = 0x142D058B0 #0x142D058A8
end_address = 0x147BBB400

# Start processing executable segments
process_executable_segments_within_range(start_address, end_address)

print('\n---Ending Cleanup_Functions---\n')
