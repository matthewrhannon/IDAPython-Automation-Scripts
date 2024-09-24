
import idaapi
import idc
import ida_bytes
import ida_nalt
import ida_hexrays
import ida_kernwin
import re

def use_regex(input_text):
    pattern = re.compile(r"^; OFF64 SEGDEF \[_text,[A-Za-z0-9]+\]$", re.IGNORECASE)
    
    ret = pattern.match(input_text)
    if not ret or ret == None:
        return False
    else:
        return True
    
def define_func_ptrs(start_ea, end_ea):
    try:
        ida_kernwin.show_wait_box("Processing segments...\n\nPress 'Cancel' to stop the script.")
        
        old_ea = start_ea
        current_ea = start_ea
        
        print("Jumping to address = " + hex(start_ea))
        current_ea = ida_kernwin.jumpto(start_ea)
        
        while current_ea <= end_ea:
            current_ea = here()
            
            disasm = generate_disasm_line(current_ea, 0)
            print("disasm = " + str(disasm))
            
            #Remove far flag if it exists inside pre-existing function
            #disasm1 = generate_disasm_line(curr_addr, 1)
            #FIXME: add code to remove far flag
            
            if ((current_ea & MS_CLS) == FF_DATA):
                print("WARNING: skippig cause already data defined at " + hex(current_ea))
                
                current_ea = current_ea + 0x08
                current_ea = ida_kernwin.jumpto(current_ea)
                
                if ida_kernwin.user_cancelled():
                    print("Script cancelled by user.")
                    return
                    
                continue
            
            if use_regex(str(disasm)):
                idc.op_offset(current_ea, 0, idc.REF_OFF64)
                current_ea = current_ea + 0x08
            else:
                print("Skipping because bad regex" + str(disasm))
                
                #disasm = generate_disasm_line(curr_addr, 1)
                #addy = str(disasm).split(
                '''
                current_ea = idc.next_head(current_ea) #idc.here() #idc.next_head(current_ea)
                if ida_kernwin.user_cancelled():
                    print("Script cancelled by user.")
                    return
                '''
                current_ea = current_ea + 0x08
                current_ea = ida_kernwin.jumpto(current_ea)
                continue
           
            '''
            old_ea = current_ea

            if current_ea == BADADDR:
                current_ea = current_ea + 0x08
            else:
                print("GOOD: Inside else clause - current_ea = " + hex(current_ea))
            '''
            
            '''
            current_ea = idc.next_head(current_ea) #idc.here() #idc.next_head(current_ea)
            if ida_kernwin.user_cancelled():
                print("Script cancelled by user.")
                return
            '''
             
            #print("Jumping to address = " + hex(current_ea))
            current_ea = ida_kernwin.jumpto(current_ea)
            
            if ida_kernwin.user_cancelled():
                print("Script cancelled by user.")
                return
            
            continue
            
        print("Done!")
        return
    except OSError as err:
        print("OS error:", err)
        if ida_kernwin.user_cancelled():
            print("Script cancelled by user.")
            return
        raise
    except ValueError:
        print("Could not convert data to an integer.")
        if ida_kernwin.user_cancelled():
            print("Script cancelled by user.")
            return
        raise
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        if ida_kernwin.user_cancelled():
            print("Script cancelled by user.")
            return
        raise
    except:
        print("ERROR: exception caught. TODO: add exceptionn! Raising!")
        if ida_kernwin.user_cancelled():
            print("Script cancelled by user.")
            return
        raise
    finally:
        ida_kernwin.hide_wait_box() 
        print("\n\n\n!!! FINALLY !!!\n\n\n")
        
start_address = 0x142D058B0 #0x1426612A0 #0x0000000142D05898  # Replace with your desired start address
end_address = 0x1438FCFFF #0x142FCD610 #0x14266235F #0x00000001438FCE20    # Replace with your desired end address

print("Starting to define funtion pointers in rdata section...")
define_func_ptrs(start_address, end_address)
