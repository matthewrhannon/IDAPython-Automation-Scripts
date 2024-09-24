import idaapi
import idc
import ida_bytes
import ida_nalt

def is_valid_string(ea, string_type):
    """
    Checks if the given address contains a valid string of the specified type.
    """
    length = ida_bytes.get_max_strlit_length(ea, string_type)
    return length > 0

def define_strings_in_range(start_ea, end_ea):
    """
    Scans a memory range and attempts to define ASCII and Unicode strings.
    """
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

# Example usage: define strings in a specified range
#start_address = 0x142D058A8
#end_address = 0x147BBB400
start_address = 0x142CF68B0 #0x1426612A0 #0x0000000142D05898  # Replace with your desired start address
end_address = 0x147BA35FF #0x14266235F #0x00000001438FCE20    # Replace with your desired end address
define_strings_in_range(start_address, end_address)


'''
import idaapi
import idc
import ida_bytes
import ida_nalt

def is_valid_string(ea, string_type):
    """
    Checks if the given address contains a valid string of the specified type.
    """
    length = ida_bytes.get_max_strlit_length(ea, string_type)
    return length > 0

def define_strings_in_range(start_ea, end_ea):
    """
    Scans a memory range and attempts to define ASCII, Unicode, and UTF-8 strings.
    """
    current_ea = start_ea

    while current_ea < end_ea:
        defined = False
        
        # Check for ASCII string
        if is_valid_string(current_ea, ida_nalt.STRTYPE_C):
            length = ida_bytes.get_max_strlit_length(current_ea, ida_nalt.STRTYPE_C)
            ida_bytes.create_strlit(current_ea, current_ea + length, ida_nalt.STRTYPE_C)
            string_contents = ida_bytes.get_strlit_contents(current_ea, length, ida_nalt.STRTYPE_C)
            if string_contents:
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

        # Check for UTF-8 string
        elif is_valid_string(current_ea, ida_nalt.STRTYPE_C_8):
            length = ida_bytes.get_max_strlit_length(current_ea, ida_nalt.STRTYPE_C_8)
            ida_bytes.create_strlit(current_ea, current_ea + length, ida_nalt.STRTYPE_C_8)
            string_contents = ida_bytes.get_strlit_contents(current_ea, length, ida_nalt.STRTYPE_C_8)
            if string_contents:
                print(f"Defined UTF-8 string at {hex(current_ea)}: {string_contents.decode('utf-8', errors='ignore')}")
            defined = True
        
        # Move to next address if no string was defined
        if defined:
            current_ea += length
        else:
            current_ea += 1

# Example usage: define strings in a specified range
start_address = 0x142D058A8
end_address = 0x147BBB400
define_strings_in_range(start_address, end_address)
'''