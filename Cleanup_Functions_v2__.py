import idautils
import idaapi
import idc
import ida_bytes
import ida_funcs
import ida_kernwin
import nltk
from nltk.corpus import words
import string
import ida_nalt

def is_valid_string(ea, string_type):
    """
    Checks if the given address contains a valid string of the specified type.
    """
    length = ida_bytes.get_max_strlit_length(ea, string_type)
    return length > 0

# Ensure the necessary resources are downloaded
nltk.download('words')

# Load the word list
english_words = set(words.words())

# Function to check if a string is a valid word
def is_valid_word(s):
    
    #Make sure it is a string type
    res = issubclass(type(s), str)
    if res == False:
        return False
    
    english_word_counter = 0
    parts = s
    
    for part in parts.split():
       if  part.lower() in english_words:
           english_word_counter = english_word_counter + 1
    
    if english_word_counter >= 1:
        return True
    else:
        return False

# Function to extract a potential string from memory and check if it is a valid word
#def check_memory_for_string(ea, length=100: Note: change made 9/19/2024 @ 6:40 pm
def check_memory_for_string(ea, length=256): #Note: was 100
    encodings = ['utf-8', 'ascii', 'utf-16', 'utf-32']
    str_types = [idc.STRTYPE_C, idc.STRTYPE_UNICODE]
    
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
    return xrefs_count

# Main function to define data at an undefined address and check cross-references
def define_data_with_xref_and_string_check(ea):
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
            print("Reached the largest data type.")
            break

        # Update the original_xrefs for the next iteration
        original_xrefs = current_xrefs

def undefine_instructions_in_rdata(start_ea, end_ea):
    """Undefine any instructions in the .rdata segment and try to identify valid data."""
    print(f"Undefining instructions in .rdata from 0x{start_ea:X} to 0x{end_ea:X}.")
    ea = start_ea
    while ea < end_ea:
        flags = idc.get_full_flags(ea)
        if ida_bytes.is_code(flags):
            print(f"Undefining instruction at 0x{ea:X}.")
            idc.del_items(ea, idc.DELIT_SIMPLE)
        ea = idc.next_head(ea)

def define_strings_in_rdata(start_ea, end_ea):

    current_ea = start_ea

    while current_ea < end_ea:
        defined = False
        
        # Check for ASCII/UTF-8 string
        if is_valid_string(current_ea, ida_nalt.STRTYPE_C):
            length = ida_bytes.get_max_strlit_length(current_ea, ida_nalt.STRTYPE_C)
            ida_bytes.create_strlit(current_ea, current_ea + length, ida_nalt.STRTYPE_C)
            string_contents = ida_bytes.get_strlit_contents(current_ea, length, ida_nalt.STRTYPE_C)
            if string_contents:
                try:
                    print(f"Defined ASCII/UTF-8 string at {hex(current_ea)}: {string_contents.decode('utf-8')}")
                except UnicodeDecodeError:
                    print(f"Defined ASCII string at {hex(current_ea)}: {string_contents.decode('ascii', errors='ignore')}")
            defined = True

        # Check for Unicode string
        elif is_valid_string(current_ea, ida_nalt.STRTYPE_C_16):
            length = ida_bytes.get_max_strlit_length(current_ea, ida_nalt.STRTYPE_C_16)
            ida_bytes.create_strlit(current_ea, current_ea + length, ida_nalt.STRTYPE_C_16)
            string_contents = ida_bytes.get_strlit_contents(current_ea, length, ida_nalt.STRTYPE_C_16)
            if string_contents:
                print(f"Defined Unicode string at {hex(current_ea)}: {string_contents.decode('utf-16', errors='ignore')}")
            defined = True
        
        # Move to next address if no string was defined
        if defined:
            current_ea += length
        else:
            current_ea += 1

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
    base_addr = 0
    
    # Resolve the base_str to an actual address if it's a label
    if not base_str.startswith('0x') and not base_str.isdigit():
        base_addr = idc.get_name_ea_simple(base_str)
        if base_addr == idaapi.BADADDR:
            print(f"Error: Could not resolve symbol {base_str} to an address.")
            return None
        else:
            print(f"Resolved symbol {base_str} to address 0x{base_addr:X}.")
    else:
        try:
            base_addr = int(base_str, 16)
            print(f"Parsed base address: 0x{base_addr:X}")
        except ValueError:
            print(f"Error: Invalid base address {base_str}.")
            return None

    # Strip out any extraneous text after the offset (e.g., "; 2 2 2 2" or "h")
    if offset_str != None and offset_str != '' and offset_str != BADADDR:
        offset_str = offset_str.split(';')[0].strip().rstrip('h').rstrip('H')
    
    try:
        offset = int(offset_str, 16)
        print(f"Parsed offset: 0x{offset:X}")
    except ValueError:
        base_addr = int(base_str, 16)
        resolved_address = base_addr
        print(f"Computed RVA: 0x{resolved_address:X}")
        return resolved_address
        #print(f"Error: Invalid offset {offset_str}.")
        #return None
    
    resolved_address = base_addr + offset
    print(f"Computed RVA: 0x{resolved_address:X}")
    return resolved_address

def undefine_area(start_ea, end_ea):
    """Undefine all instructions and data in the specified range."""
    print(f"Undefining area from 0x{start_ea:X} to 0x{end_ea:X}.")
    ea = start_ea
    while ea < end_ea:
        flags = idc.get_full_flags(ea)
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

def is_within_segment(ea):
    """Check if the given address is within a valid segment."""
    seg = idaapi.getseg(ea)
    if seg:
        return seg.start_ea <= ea < seg.end_ea
    return False

def aggressively_undefine_surrounding_area(ea, range_size=0x10):
    """Undefine the area around the current address, looking upwards and downwards."""
    seg = idaapi.getseg(ea)
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
        end_ea = rva + 0x10  # Adjust this size as needed

    print(f"Attempting to create function at 0x{rva:X} with end at 0x{end_ea:X}.")
    
    # Undefine any existing code or data in the range
    undefine_area(rva, end_ea)
    
    ea = rva
    while ea < end_ea:
        if ida_kernwin.user_cancelled():
            print("Script cancelled by user.")
            return False
        if not ida_bytes.is_code(idc.get_full_flags(ea)):
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
        #print(f"Function already exists at 0x{rva:X}.")
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
                    #print('disasm_line=' + str(disasm_line))
                    
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
                                else:
                                    print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")
                            #else:
                            #    print(f"Skipping line '{disasm_line}' as it does not match expected format.")
                        except Exception as e:
                            print(f"Error processing line '{disasm_line}': {e}")
                            
                    # Check if the disassembly contains "dq offset unk_" or "dq offset loc_"
                    elif "dq offset unk_" in disasm_line or "dq offset loc_" in disasm_line:
                        # Split the line and get the part after "unk_" or "loc_"
                        if "dq offset unk_" in disasm_line:
                            try:
                                # Extract the hex value right after "unk_"
                                hex_str = disasm_line.split("dq offset unk_")[1].split()[0]
                                hex_str = hex_str.split(';')[0].strip().rstrip('h').rstrip('H')
                                # Ensure it's a valid hexadecimal number
                                rva = int(hex_str, 16)
                                
                                if rva is not None:
                                    rva_address = rva
                                    # Check if there's a function at this address
                                    func = ida_funcs.get_func(rva_address)
                                    if func:
                                        # Undefine the function
                                        if idc.del_func(rva_address):
                                            print(f"Successfully undefined function at {rva}")
                                        else:
                                            print(f"WARNING Failed to undefine function at {rva}")
                                            #continue
                                        
                                        # Redefine the function
                                        if idc.add_func(rva_address):
                                            print(f"Successfully redefined function at {rva}")
                                        else:
                                            print(f"Failed to redefine function at {rva}")
                                    else:
                                        rva_address = rva
                                        print(f"No function found at {rva}")
                                        # Redefine the function
                                        if idc.add_func(rva_address):
                                            print(f"Successfully redefined function at {rva}")
                                        else:
                                            print(f"Failed to redefine function at {rva}")                                  
                                    '''
                                    if not process_function_at_rva(rva):
                                        print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
                                        create_valid_function(rva)
                                    else:
                                        print(f"Valid function processed at 0x{rva:X}.")
                                    '''                                    
                                else:
                                    print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")
                                # Print the effective address, disassembly line, and the extracted hex string
                                #print(f"1Found at {hex(ea)}: {hex_str} - {disasm_line}")
                            except Exception as e:
                                print(f"Failed to parse hex from 'unk_' at {hex(ea)}")
                                #ea += 8
                                #continue
                        elif "dq offset loc_" in disasm_line:
                            try:
                                # Extract the hex value right after "loc_"
                                hex_str = disasm_line.split("dq offset loc_")[1].split()[0]
                                hex_str = hex_str.split(';')[0].strip().rstrip('h').rstrip('H')
                                # Ensure it's a valid hexadecimal number
                                rva = int(hex_str, 16)
                                if rva is not None:
                                    rva_address = rva
                                    # Check if there's a function at this address
                                    func = ida_funcs.get_func(rva_address)
                                    if func:
                                        # Undefine the function
                                        if idc.del_func(rva_address):
                                            print(f"Successfully undefined function at {rva}")
                                        else:
                                            print(f"WARNING: Failed to undefine function at {rva}")
                                            #continue
                                        
                                        # Redefine the function
                                        if idc.add_func(rva_address):
                                            print(f"Successfully redefined function at {rva}")
                                        else:
                                            print(f"Failed to redefine function at {rva}")
                                    else:
                                        rva_address = rva
                                        print(f"No function found at {rva}")
                                        # Redefine the function
                                        if idc.add_func(rva_address):
                                            print(f"Successfully redefined function at {rva}")
                                        else:
                                            print(f"Failed to redefine function at {rva}")

                                    '''
                                    if not process_function_at_rva(rva):
                                        print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
                                        create_valid_function(rva)
                                    else:
                                        print(f"Valid function processed at 0x{rva:X}.")
                                    '''
                                else:
                                    print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")                                
                                # Print the effective address, disassembly line, and the extracted hex string
                                #print(f"2Found at {hex(ea)}: {hex_str} - {disasm_line}")  
                            except Exception as e:
                                print(f"Failed to parse hex from 'loc_' at {hex(ea)}")
                                #ea += 8
                                #continue
                        else:
                            print(f"!!!! WARNING - inside else - at {hex(ea)}: - {disasm_line} !!!!")  

        
                    # Move to the next potential 'dq' entry (assuming 8-byte alignment)
                    #ea += 8

                    ea = idc.next_head(ea)
                    if ida_kernwin.user_cancelled():
                        print("Script cancelled by user.")
                        return
    except Exception as e:
        print(f"Error processing line '{disasm_line}': {e}")    
    finally:
        ida_kernwin.hide_wait_box()

def PLUGIN_ENTRY():
    print('Starting Cleanup_Functions_v2 Script!')
    
    # Process the .rdata segment first to clean it up
    #process_rdata_segment()

    # Specify the range you want to process in executable segments
    #start_address = 0x142D058A8
    #end_address = 0x147BBB400
    start_address = 0x142D128B0 #0x142D058B0 #0x142CF68B0 #0x1426612A0 #0x0000000142D05898  # Replace with your desired start address
    end_address = 0x1433E27C0 #0x1438FCE48 #0x14266235F #0x00000001438FCE20    # Replace with your desired end address

    # Start processing executable segments
    process_executable_segments_within_range(start_address, end_address)
    
    print('Finished Cleanup_Functions_v2 Script!')
    
    
'''        
elif 'dq offset unk_ ' in disasm_line:
    try:
        parts = disasm_line.split('dq offset unk_')
        print('dq offset unk_' + ' + ' + str(parts))
        #if len(parts) > 1: #in parts[1]:
        for part in parts:
            print('1part=' + str(part))
            
        base_and_offset = parts[1].strip()
        rva = get_rva(base_and_offset)
        #rva = base_and_offse
        print('2 - rva=' + hex(rva))
        if rva is not None:
            if not process_function_at_rva(rva):
                print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
                create_valid_function(rva)
            else:
                print(f"Valid function processed at 0x{rva:X}.")
        else:
            print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")
        #else:
        #    print(f"Skipping line '{disasm_line}' as it does not match expected format.")
    except Exception as e:
        print(f"Error processing line '{disasm_line}': {e}")
elif 'dq offset loc_ ' in disasm_line:
    try:
        parts = disasm_line.split('dq offset loc_')
        print('dq offset loc_' + ' + ' + str(parts))

        #if len(parts) > 1: #in parts[1]:
        for part in parts:
            print('2part=' + hex(part))
            
        base_and_offset = parts[1].strip()
        rva = get_rva(base_and_offset)
        #rva = base_and_offset
        print('3 - rva=' + hex(rva))
        if rva is not None:
            if not process_function_at_rva(rva):
                print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
                create_valid_function(rva)
            else:
                print(f"Valid function processed at 0x{rva:X}.")
        else:
            print(f"Skipping line '{disasm_line}' due to invalid RVA computation.")
    #else:
    #    print(f"Skipping line '{disasm_line}' as it does not match expected format.")
    except Exception as e:
        print(f"Error processing line '{disasm_line}': {e}")
    
    #ea = idc.get_screen_ea()  # Use the current address in IDA
    #define_data_with_xref_and_string_check(ea)

elif 'db ' in disasm_line:
    # Handle defining strings (ASCII) in .rdata or any segment
    string_content = disasm_line.split('db ')[1].strip()
    
    
    ea = idc.get_screen_ea()  # Use the current address in IDA
    define_data_with_xref_and_string_check(ea)
else:
    print(f"No db found at '{disasm_line}'. Turning to string...")
                            
    define_strings_in_rdata(ea,  ( len(string_content)*2 ) + 1 )
    define_strings_in_rdata(ea,  ( len(string_content)*1 ) + 0 )
'''  