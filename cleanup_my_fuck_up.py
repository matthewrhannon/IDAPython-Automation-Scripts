#!/usr/bin/env python3

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

import sys

def main():
    #if len(sys.argv) != 2:
    #    print("Usage: python script.py input.txt")
    #    sys.exit(1)
    
    filename = "C:\\Users\\Unknown\\Documents\\addys.txt" #sys.argv[1]

    try:
        with open(filename, 'r') as file:
            for line_num, line in enumerate(file, 1):
                # Remove leading/trailing whitespace
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Remove '0x' or '0X' prefix if present
                if line.lower().startswith('0x'):
                    hex_str = line[2:]
                else:
                    hex_str = line
                
                # Remove any spaces or tabs within the hex string
                hex_str = ''.join(hex_str.split())
                
                try:
                    # Convert hex string to integer
                    int_value = int(hex_str, 16)
                    
                    # Call the process_me function with the integer value
                    process_bad_function(int_value)
                except ValueError:
                    print(f"Invalid hex value on line {line_num}: {line}")
    except FileNotFoundError:
        print(f"File not found: {filename}")


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
        
    print('DEBUG: s=' + s)
    
    english_word_counter = 0
    parts = s
    
    for part in parts.split():
       if  part.lower() in english_words:
           english_word_counter = english_word_counter + 1
           
    print('DEBUG: english_word_counter=0x' + hex(english_word_counter))
    
    if english_word_counter >= 1:
        return True
    else:
        return False

# Function to extract a potential string from memory and check if it is a valid word
#def check_memory_for_string(ea, length=100: Note: change made 9/19/2024 @ 6:40 pm
#def check_memory_for_string(ea, length=512):
def check_memory_for_string(ea, length=256):
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
       #undefine_area(func.start_ea, func.end_ea)
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
        
def process_bad_function(rva):
    try:
        # Ensure it's a valid hexadecimal number
        #rva = int(hex_str, 16)
        undefine_function(rva)
        if rva is not None:
            #if not process_function_at_rva(rva):
            #    print(f"Invalid function at 0x{rva:X}. Cleaning up and redefining.")
            create_valid_function(rva)
            #else:
            #    print(f"Valid function processed at 0x{rva:X}.")
        else:
            print(f"Skipping line due to invalid RVA computation.")
    except:
        print('!!! EXCEPTION CAUGHT !!!')
        
def PLUGIN_ENTRY():
    print('Starting fuck upd fixer script')
    
    main()
    
    print('Ending fuck upd fixer script')
