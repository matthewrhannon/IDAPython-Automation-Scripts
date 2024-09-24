#try:
#   import ida_idaapi as idaapi
#except Exception:
#   print("WARNING: ida_idaapi un-importable! Falling back to idaapi...")
#import idaapi
   #pass
   
from idaapi import *
from idautils import *
from idc import *
from ida_bytes import del_items, DELIT_EXPAND

import ida_kernwin
import ida_segment
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_funcs
import ida_bytes
import ida_ua

import idautils
import idc

import sark
import time
import random
import re

from goto import with_goto

print("Script rdata_fix.py 4/12/2024 - updated 4/25/2024")

def wait_for_one_sec():
    idc.qsleep(1000)
    return 1
    
# get the flags
#f = ida_bytes.get_flags(caller)
# no code there?
#if not ida_bytes.is_code(f):
#    ida_ua.create_insn(caller)

def AddressToEA(addr):
    """Converts a Ghidra Address object to an ea"""
    return ea_t.init(addr.getOffset(), addr)

def eaToAddress(ea):
    """Converts an effective address to a Ghidra Address object"""

    if isinstance(ea, ea_t):
        return ea.address
    elif idautils.is_number(ea):
        addrs = idaapi._currentProgram.parseAddress("0x%x" % ea)
        # Return the first memory address
        for addr in addrs:
            if addr.isMemoryAddress():
                return addr
    else:
        # No conversion needed
        return ea
        
    return 0
    
def go_to_address_via_string(string_to_find, retAddr):

    string_to_go = int(string_to_find, 16)
    #string_to_go = ida_bytes.create_data(string_to_find, FF_QWORD, 8, idc.BADADDR)
    #string_to_go = eaToAddress(string_to_go)
    #print("int(str((string_to_go, 16))=" + int(str(string_to_go), 16))
    if string_to_go != idc.BADADDR:
    
        start_ea = 0
        end_ea = 0
        is_func = False
        
        #print("DEBUG: before BEFORE...")
        #print("BEFORE: string_to_go=" + str(string_to_go) + ":" + " string_to_find=" + str(string_to_find))
        #string_to_go = hex(string_to_find)
        #string_to_go = eaToAddress(string_to_find)
        #print("AFTER: string_to_go=" + hex(string_to_go) + ":" + " string_to_find=" + hex(string_to_find))
        
        #print("string_to_go=" + hex(string_to_go) + ":" + " string_to_find=" + str(string_to_find))
        #string_to_go = idc.to_ea(string_to_go)
        #idc.jumpto(string_to_go)
        #string_to_go = hex(string_to_go)
        #string_to_go = AddressToEA(string_to_go)
        ida_kernwin.jumpto(string_to_go)
    
    
    #string_to_go = idaapi._currentProgram.parseAddress(string_to_find)
    if not ida_funcs.get_func(string_to_go):
        #print("NOTE: NOT A FUNCTION - " + hex(string_to_go) + "!")
        #ida_kernwin.jumpto(retAddr)
        #return 1
        
        #now = here()
        #print(('[+] CurPos: ' + hex(now)))     
        
        is_func = False

        if not ida_bytes.del_items(string_to_go, idc.DELIT_EXPAND, string_to_go+9):
            print("ERROR: couldn't delete string_to_go=" + hex(string_to_go) + " throguh string_to_go+9=" + hex(string_to_go+9) + " Returning!")
            ida_kernwin.jumpto(retAddr)
            
            return 0
        else:
        
            ida_kernwin.jumpto(string_to_find)
            
            #ida_bytes.del_items(here()-1, ida_bytes.DELIT_SINGLE, 1)
            ida_bytes.del_items(here()+0, ida_bytes.DELIT_SINGLE, 0x17)
            #ida_bytes.del_items(here()+1, ida_bytes.DELIT_SINGLE, 1)

            ida_kernwin.jumpto(string_to_find)
            
            '''
            ea1 = idc.here()
            #idc.AnalyzeArea(ea1)
            ida_bytes.del_items(here(), 0)
            ida_bytes.del_items(here()+1, 0)
            ida_bytes.del_items(here()-1, 0)
            
            size = 9
            ida_bytes.del_items(here(), DELIT_EXPAND, size)
            ida_bytes.del_items(here()-size, DELIT_EXPAND, size)
            '''
            
            #MakeUnkn(here(), DOUNK_SIMPLE)
            #ida_bytes.del_items(start_ea, DELIT_SIMPLE, end_ea - start_ea)
            #create_insn(here())
            
            ea = idc.here()
            end_ea = ea+1
            while ea < end_ea:
                # Attempt to create an
                insn_len = idc.create_insn(ea)
                if insn_len > 0:
                    #print(f"Instruction created at {hex(ea)}")
                    ea += insn_len  # Move to the next address after the created instruction
                else:
                    print(f"Failed to create instruction at {hex(ea)}")
                    ea += 1  # Move to the next byte and try again
                    
            #idaapi.create_insn(ea1)
            #insn = ida_ua.insn_t()
            #ida_ua.create_insn(insn, string_to_go)
            if not ida_funcs.add_func(string_to_find):
                print(f"Failed to create function at {hex(string_to_go)}")
            #else:
                #print(f"Function successfully created at {hex(string_to_go)}")
                
            ida_kernwin.jumpto(retAddr)
            
            return 1
    else:
        #print("NOTE: IS A FUNCTION - " + hex(string_to_go) + "!")
        
        now = idc.here()
        #print(('[+] CurPos: ' + hex(now)))
        
        cur_func = idc.get_name_ea_simple(idc.get_func_name(idc.here()))
        #print(('[+] CurFunc: ' + hex(cur_func)))
        
        start_ea = idc.get_func_attr(now, idc.FUNCATTR_START)
        end_ea = idc.get_func_attr(now, idc.FUNCATTR_END)
        #print(('[+] FuncStart: ' + hex(func_start)))
        #print(('[+] FuncEnd: ' + hex(func_end)))        
        
        is_func = True
    
        #ida_funcs.del_func(start_ea)
        
        if not ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, end_ea - start_ea):  
            print("WARNING: couldn't delete function starting at start_ea=" + hex(start_ea) + " Returning!")
            ida_kernwin.jumpto(retAddr)
            
            return 0
        else:
        
            ida_kernwin.jumpto(string_to_find)

            #.del_items(string_to_go.ea, ida_bytes.DELIT_EXPAND, string_to_go.address+9):
            #ida_bytes.del_items(idc.here()-1, ida_bytes.DELIT_EXPAND, 1)
            ida_bytes.del_items(idc.here(), ida_bytes.DELIT_EXPAND, 0x17)
            #ida_bytes.del_items(idc.here()+1, ida_bytes.DELIT_EXPAND, 1)
            
            ida_kernwin.jump(string_to_find)
            
            '''
            ea2 = idc.here()
            #idaapi.create_insn(ea2)
            #idc.AnalyzeArea(ea2)
            #ida_bytes.del_items(here(), 0)
            ida_bytes.del_items(here()+1, 0)
            ida_bytes.del_items(here()-1, 0)
            
            size = 9
            ida_bytes.del_items(here(), DELIT_EXPAND, size)
            ida_bytes.del_items(here()-size, DELIT_EXPAND, size)
            '''
            
            ea = idc.here()
            while ea < end_ea:
                # Attempt to create an
                insn_len = idc.create_insn(ea)
                if insn_len > 0:
                    #print(f"Instruction created at {hex(ea)}")
                    ea += insn_len  # Move to the next address after the created instruction
                else:
                    print(f"Failed to create instruction at {hex(ea)}")
                    ea += 1  # Move to the next byte and try again
            #MakeUnkn(here(), DOUNK_SIMPLE)
            #create_insn(here())
            #insn = ida_ua.insn_t()
            #ida_ua.create_insn(insn, string_to_go)      
            if not ida_funcs.add_func(string_to_find):
                print(f"Failed to create function at {hex(string_to_go)}")
            #else:
                #print(f"Function successfully created at {hex(string_to_go)}")
                
            ida_kernwin.jumpto(retAddr)
            
            return 1
    #else:
    #    print("WARNING: if string_to_go == idc.BADADDR! Returning!") 
    #    return 0  
  
    return 1
    
def find_rdata_start():
    for s in idautils.Segments():
        if idc.get_segm_name(s) == ".rdata":
            #print("Found .rdata start @ 0x" + hex(s) + ".")
            return s
        elif s != "":
            continue
        elif s == "":
            print("s == \"\"")
            return None
        elif s == idc.BADADDR:
            print("s == idc.BADADDR")
            return None
        else:
            print("WARNING: else encounted...")
            return None

#Credit: https://reverseengineering.stackexchange.com/questions/13454/get-a-list-of-global-variables-with-ida-python
#Second option - iteration over lines
def get_segment_names2(name):
    seg = sark.Segment(name=name)
    for line in seg.lines:
        yield line.ea, sark.Line(ea=line.ea)
        #if line.has_name:
        #    yield line.ea, line.name
    return
 
def add_hex(a, b):
  """Adds two hexadecimal numbers.

  Args:
    a: A hexadecimal number.
    b: A hexadecimal number.

  Returns:
    The sum of a and b in hexadecimal.
  """

  # Convert the hexadecimal numbers to integers.
  a = int(a, 16)
  b = int(b, 16)

  # Add the integers.
  sum = a + b

  # Convert the sum back to hexadecimal.
  sum = hex(sum)

  # Return the sum.
  return sum
 
ea = 0
name = 0
Good = False
count_num = 0

#/dq\s+offset\s+(?:(?!\+).)*\+.*/g
#dq\s+offset\s+(?:(?!\+).)*\+.*
regexme = re.compile('dq\s+offset\s+(?:(?!\+).)*\+.*')
UnWantedPattern0 = re.compile(r"\+\+")
UnWantedPattern1 = re.compile(r"\;")

@with_goto
def Main():

    print("NOTE: inside Main...")
    ida_kernwin.show_wait_box("Processing")
    
    global Good
    global ea
    global name
    global count_num
    good_to_go = 0
    
    try:
        rdata_start = find_rdata_start()
        if rdata_start == None:
            print("ERROR: rdata_start == None")
            return False
        #else:
            #print("rdata_start=" + hex(rdata_start) + "...")

        #print("Lines inside .rdata:")
        if good_to_go == 1:
            label .bar_begin
            print("...OUT OF GOTO...")
            good_to_go = 0
            #continue
        else:
            good_to_go = 1
                    
        for ea, name in get_segment_names2('.rdata'):
            if ida_kernwin.user_cancelled():
                #print("0x"+ hex(ea) + ": " + str(name))
                #print("WARNING: ida_kernwin.user_cancelled exit route! count_num="  + str(count_num))
                Good = False
                break
                
            else:

                reggy = regexme.search(str(name))
                if reggy != None:
                    badMatch0 = UnWantedPattern0.search(str(name))
                    
                    if badMatch0 != None:
                        #print("WARNING: ++ found... ea=" + hex(ea))
                        continue
                    else:   
                        badMatch1 = UnWantedPattern1.search(str(name))
                        if badMatch1 != None:
                            #print("WARNING: ; found...ea=" + hex(ea))
                            continue
                        else:
                            third_part = str(str(name).split()[3])
                            #print("third_part=" + str(third_part))
                            address_and_plus_sign_and_number = str(third_part.split("loc_")[1])
                            #print("address_and_plus_sign_and_number=" + str(address_and_plus_sign_and_number))
                            address = str(address_and_plus_sign_and_number.split("+")[0])
                            #print("address=" + str(address))
                            number = str(address_and_plus_sign_and_number.split("+")[1])
                            #print("number=" + str(number))
                            
                            address_int = int("0x" + str(address), 16)
                            address_hex = hex(address_int)
                                                        
                            number_int = int("0x" + str(number), 16)
                            number_hex = hex(number_int)

                            #print("222DEBUG222")
                            #print("address_hex=" + str(address_hex))
                            #print("number_hex=" + str(number_hex))
                            #x1 = int(str(name).split()[3].split("loc_")[1].split('+")[0])
                            #print("x1=" + str(x1))
                            #x2 = int(str(name).split()[3].split("loc_")[1].split('+")[1])
                            #print("x2=" + str(x2))
                            #x = hex(addrsss_hex) + hex(number_hex)
                            x = add_hex(address_hex, number_hex)
                            print(str(x))
                            #if not x:
                            #    print("ERROR: x == bad nummber! hex(x)=" + hex(x))
                            #    break
                            #else:
                            #    print(s
                            #    if go_to_address_via_string(x, ea) == 0:
                            #        print("WARNING: go_to_address_via_hex(" + str(x) + ") == 0!")
                            #       continue
                            #    else:
                            #        print("!!! GOT ONE !!!")
                                    
                            #        count_num = count_num + 1
                            continue
                else:
                    #print("WTF")
                    continue

        #print("Done printing .rdata lines! count_num=" + str(count_num))
        Good = True

    except Exception as e:
        print("WARNING: exception happened! str(e)=" + str(e))
        print("(ea, name, Good)=(" + hex(ea) + ", " + str(name) + ", " + str(Good) + ")")
        #pass
        goto .bar_begin
    finally:
        if Good == False:
            print(hex(ea) + ": " + str(name))
            print("WARNING: finally exit route! count_num="  + str(count_num))
            ida_kernwin.hide_wait_box()
            return False
        else:
            print("SUCCESS: good rdata_fix.py run!")
            ida_kernwin.hide_wait_box()
            return True
    
'''
    now = here()
    print(('[+] CurPos: ' + hex(now)))
    cur_func = get_name_ea_simple(get_func_name(here()))
    print(('[+] CurFunc: ' + hex(cur_func)))
    func_start = idc.get_func_attr(now, FUNCATTR_START)
    func_end = idc.get_func_attr(now, FUNCATTR_END)
    print(('[+] FuncStart: ' + hex(func_start)))
    print(('[+] FuncEnd: ' + hex(func_end)))
    
    curr_addr = func_start
    while curr_addr < func_end:
        disasm = generate_disasm_line(curr_addr, 1)
        print((hex(curr_addr) + '\t' + disasm))
        
        is_obfuscated = False
            
        #Obfuscated Pattern Start
        if ('short near ptr' in disasm):
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if not 'nop' in next_disasm:
                if disasm[0] == 'j':
                    is_obfuscated = True
        elif (', cs:dword' in disasm):
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if 'add' in next_disasm:
                next_disasm = generate_disasm_line(next_head(next_head(next_head(curr_addr))), 1)
                if 'cmp' in next_disasm:
                    start_addr = curr_addr
                    end_addr = 0
                    while end_addr == 0:
                        disasm = generate_disasm_line(start_addr, 1)
                        print((hex(start_addr) + ' - ' + disasm))
                        if ('short' in disasm) and (disasm[0] == 'j'):
                            end_addr = start_addr
                            break
                        start_addr = next_head(start_addr)
                    if end_addr:
                        for i in range(curr_addr, end_addr):
                            idc.patch_byte(i, 0x90)
                        curr_addr = end_addr
                        is_obfuscated = True
        elif ('jz' in disasm):
            prev_disasm = generate_disasm_line(prev_head(curr_addr), 1)
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if not 'nop' in next_disasm:
                if 'cmp' in prev_disasm:
                    if get_operand_value(prev_head(curr_addr), 1) == 0xE8:
                        is_obfuscated = True
        #Obfuscated Pattern End
        
        if (is_obfuscated):
            jmp_addr = get_operand_value(curr_addr,0)
            jmp_next = next_head(jmp_addr)
            print(('[!] Found obfuscated jmp at ' + hex(curr_addr) + ' to ' + hex(jmp_addr)))
            for i in range(curr_addr, jmp_addr):
                idc.patch_byte(i, 0x90)
            break
        curr_addr = next_head(curr_addr)                #is curr_addr already equal to jmp_next value?
'''

    
def PLUGIN_ENTRY():
    print("Starting .rdata fixer...")
    
    retValue = Main()
    if retValue != True:
        print("ERROR: retValue != True!")
    else:
        print("Successfully ran script!")

    #idaapi.compile_idc_text('static fn1() { RunPythonStatement("run()"); }')
    #add_idc_hotkey("F1", 'fn1')