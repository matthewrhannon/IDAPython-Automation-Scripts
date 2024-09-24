import idc
import ida_range
import ida_ida
import ida_ua

try:
    from ida_idaapi import idaapi
except Exception:
    print("WARNING: NOTICE - from ida_idaapi import idaapi threw exception!")
    import idaapi
    pass
    
import ida_search
import ida_funcs
import ida_bytes
import ida_kernwin
import ida_ida
import ida_nalt
import idautils

Happy = False

print("Script fix_cleanup.py 5/28/2024")

def intro():

    info = idaapi.get_inf_structure()
    filename = idaapi.get_input_file_path()
    entrypoint = info.start_ip
    imagebase = ida_nalt.get_imagebase()
    is_64bits = info.is_64bit()
    is_dll = info.is_dll()
    proc_name = ida_ida.inf_get_procname()
    
    print("")
    print("")
    print("info=" + str(info))
    print("filename=" + str(filename))    
    print("entrypoint=" + str(entrypoint))
    print("imagebase=" + str(imagebase))
    print("is_64bits=" + str(is_64bits))
    print("is_dll=" + str(is_dll))
    print("proc_name=" + str(proc_name))
    print("")
    print("")
    
    return True
    
def wait_for_one_sec():
    idc.qsleep(1000)
    return 1
    
def getInstructionBytes(offset):
        ins = idautils.DecodeInstruction(offset)
        ins_bytes = ida_bytes.get_bytes(offset, ins.size)
        return ins_bytes 

'''

...
...
...

.text:0000000000410108 008 58                                      pop     rax
.text:0000000000410109 000 C3                                      retn
.text:0000000000410109                             ; } // starts at 4100B0
.text:0000000000410109
.text:0000000000410109                             sub_004100B0    endp
.text:0000000000410109
.text:0000000000410109                             ; ---------------------------------------------------------------------------
.text:000000000041010A 66                                          db  66h ; f
.text:000000000041010B 0F                                          db  0Fh
.text:000000000041010C 1F                                          db  1Fh
.text:000000000041010D 44                                          db  44h ; D
.text:000000000041010E 00                                          db    0
.text:000000000041010F 00                                          db    0
.text:0000000000410110                             ; ---------------------------------------------------------------------------
.text:0000000000410110
.text:0000000000410110                             loc_00410110:                           ; CODE XREF: init+49↓p
.text:0000000000410110                                                                     ; DATA XREF: .init_array:funcs_2EEF479↓o
.text:0000000000410110                             ; __unwind {                            ; 2 2 2
.text:0000000000410110 50                                          push    rax
.text:0000000000410111 BF 74 D9 44 04                              mov     edi, offset dword_0444D974 ; 2 2 2 2
.text:0000000000410116 E8 E5 C1 24 00                              call    sub_0065C300
.text:0000000000410116
.text:000000000041011B BF C0 C6 65 00                              mov     edi, offset func ; lpfunc
.text:0000000000410120 BE 74 D9 44 04                              mov     esi, offset dword_0444D974 ; obj
.text:0000000000410125 BA 98 C9 35 04                              mov     edx, offset qword_0435C998 ; lpdso_handle
.text:000000000041012A E8 61 58 FF FF                              call    ___cxa_atexit
.text:000000000041012A
.text:000000000041012F C7 05 3F D8 03 04 00 00                     mov     cs:dword_0444D978, 0
.text:000000000041012F 00 00
.text:0000000000410139 C7 05 39 D8 03 04 00 00                     mov     cs:dword_0444D97C, 0
.text:0000000000410139 00 00
.text:0000000000410143 C7 05 33 D8 03 04 00 00                     mov     cs:dword_0444D980, 0
.text:0000000000410143 00 00
.text:000000000041014D 48 B8 00 00 80 3F 00 00                     mov     rax, 3F8000003F800000h
.text:000000000041014D 80 3F
.text:0000000000410157 48 89 05 26 D8 03 04                        mov     cs:qword_0444D984, rax
.text:000000000041015E C7 05 24 D8 03 04 00 00                     mov     cs:dword_0444D98C, 3F800000h ; <suspicious>
.text:000000000041015E 80 3F                         ; <suspicious>
.text:0000000000410168 58                                          pop     rax
.text:0000000000410169 C3                                          retn
.text:0000000000410169                             ; } // starts at 410110
.text:0000000000410169
.text:0000000000410169                             ; ---------------------------------------------------------------------------
.text:000000000041016A 66                                          db  66h ; f
.text:000000000041016B 0F                                          db  0Fh
.text:000000000041016C 1F                                          db  1Fh
.text:000000000041016D 44                                          db  44h ; D
.text:000000000041016E 00                                          db    0
.text:000000000041016F 00                                          db    0
.text:0000000000410170                             ; ---------------------------------------------------------------------------
.text:0000000000410170
.text:0000000000410170                             loc_00410170:                           ; CODE XREF: init+49↓p
.text:0000000000410170                                                                     ; DATA XREF: .init_array:funcs_2EEF479↓o
.text:0000000000410170                             ; __unwind {                            ; 2 2 2
.text:0000000000410170 50                                          push    rax
.text:0000000000410171 BF 90 D9 44 04                              mov     edi, offset qword_0444D990 ; 2 2 2 2
.text:0000000000410176 E8 85 C1 24 00                              call    sub_0065C300
.text:0000000000410176
.text:000000000041017B BF C0 C6 65 00                              mov     edi, offset func ; lpfunc
.text:0000000000410180 BE 90 D9 44 04                              mov     esi, offset qword_0444D990 ; obj
.text:0000000000410185 BA 98 C9 35 04                              mov     edx, offset qword_0435C998 ; lpdso_handle
.text:000000000041018A E8 01 58 FF FF                              call    ___cxa_atexit
.text:000000000041018A
.text:000000000041018F 58                                          pop     rax
.text:0000000000410190 C3                                          retn
.text:0000000000410190                             ; } // starts at 410170
.text:0000000000410190
.text:0000000000410190                             ; ---------------------------------------------------------------------------
.text:0000000000410191 66                                          db  66h ; f
.text:0000000000410192 2E                                          db  2Eh ; .
.text:0000000000410193 0F                                          db  0Fh
.text:0000000000410194 1F                                          db  1Fh
.text:0000000000410195 84                                          db  84h
.text:0000000000410196 00                                          db    0
.text:0000000000410197 00                                          db    0
.text:0000000000410198 00                                          db    0
.text:0000000000410199 00                                          db    0
.text:000000000041019A 00                                          db    0
.text:000000000041019B 0F                                          db  0Fh
.text:000000000041019C 1F                                          db  1Fh
.text:000000000041019D 44                                          db  44h ; D
.text:000000000041019E 00                                          db    0
.text:000000000041019F 00                                          db    0
.text:00000000004101A0                             ; ---------------------------------------------------------------------------
.text:00000000004101A0
.text:00000000004101A0                             loc_004101A0:                           ; CODE XREF: init+49↓p
.text:00000000004101A0                                                                     ; DATA XREF: .init_array:funcs_2EEF479↓o
.text:00000000004101A0                             ; __unwind {                            ; 2 2 2
.text:00000000004101A0 50                                          push    rax
.text:00000000004101A1 BF A0 D9 44 04                              mov     edi, offset off_0444D9A0 ; 2 2 2 2
.text:00000000004101A6 E8 55 C1 24 00                              call    sub_0065C300

...
...
...
'''


def fix_cleanup_funcs():

    #current_ea = 0
    count = 0
    
    #.text:00000000004117A0                             sub_004117A0    proc near               ; CODE XREF: init+49↓p                  <--- reasonable place to start testing and stopping at ed of bad section for testing
    start_effective_address = 0x4117A0
    
    #.text:0000000000432920                             sub_00432920    proc near               ; CODE XREF: init+49↓p                  <--- good place to stop early testing after major back block
    stop_effective_address = 0x432920
    
    #Flow:
    #-iterate downward starting at our effective_start_addresss (for now)
    #    -are you already apart of a fuction?
    #       -is the function you are apart of valid?
    #          -if not - destroy function and undo dissasembly
    #       -it is a valid function? - cool move on
    #    -you say you are NOT apart of a function?
    #       -okay... lets see if we can find you a function to be apart of by:
    #           -iterate upwards until you find something with xrefs (naive with many assumptions, but I think it will work in this special case)
    #           -is this place a good and valid place to create a fuction assumming it is not already a function (in that case - something went wrong - and for now log the error and move onn past the instructionn we were trying to find a home
    #           -if it is a good place to make a function - make a function there (and manaual instructions if required) - verify we found our friend a nice home and if so move on. If not - log it - and move on for now... this might be the policy we follow ultimately for success
    #    -iterate to next instruction (assemblying one if there isn't one)
    #- ??? succcss ???
    
    curr_addr_under_examination = start_effective_address
    
    #FIXME: make sure we are only processsing executable sections
    while curr_addr_under_examination < stop_effective_address:
        
        ea = here()
        
        #Make sure we have a valid instruction
        ea_flags = ida_bytes.get_flags(ea)

        insn_len = 0
        if not ida_bytes.is_code(ea_flags):
            insn_len = ida_ua.create_insn(ea)
            print("[DEBUG] Created in structionn at ea=" + hex(ea) + " and length=" + hex(insn_len))
        
        #Check if we are in a function
        curr_possible_func = ida_funcs.get_func(ea)
        if curr_possible_func:
            #Make sure we are at the start of fuction before we carry on  with the sanity logic right below this sentence
            if ida_bytes.is_func(ea) == True:
                if int(ea, 16) % 0x08 != 0:
                    print("[WARNING] Found bad function @ " + hex(ea))
                   
                    start_ea = idc.get_func_attr(curr_possible_func, idc.FUNCATTR_START)
                    end_ea = idc.get_func_attr(curr_possible_func, idc.FUNCATTR_END)
                
                    func_length = end_ea - start_ea
                    
                    ida_funcs.del_func(ea)
                    ida_bytes.del_items(ea, 0, func_length)
                    
                    continue
        else:
            #So you say you are not apart of a function
            
            

        for function_ea in idautils.Functions():
        
            if ida_kernwin.user_cancelled():
                print("WARNING: ida_kernwin.user_cancelled exit route!")
                Happy = False
                break
                
            start_ea = idc.get_func_attr(function_ea, idc.FUNCATTR_START)
            end_ea = idc.get_func_attr(function_ea, idc.FUNCATTR_END)
            
            func_length = end_ea - start_ea
           
            #current_ea = start_ea
            
            print("start_ea=" + hex(start_ea) + " --> end_ea=" + hex(end_ea) + " size=" + str(func_length))
            
            #start_ea = idc.to_ea(start_ea)
            ida_kernwin.jumpto(start_ea)
            
            #sanitycheck
            #if start_ea % 0x08 != 0:
            if start_ea % 0x04 != 0:
                print("[SANITY FAILURE] start_ea=" + hex(start_ea)+ " and end_ea=" + hex(end_ea) + "... continuing ... and destroying instructions inbetween...")
                num_bytes_to_un_encode = func_length
                
                ida_funcs.del_func(start_ea)
                ida_bytes.del_items(start_ea, 0, num_bytes_to_un_encode)
                
                continue
                
            #ida_funcs.del_func(function_ea)
            #ida_ua.create_insn(insn, start_ea)

            ida_funcs.del_func(function_ea)
            ida_ua.create_insn(start_ea)
            ida_funcs.add_func(start_ea)
            
            if not ida_bytes.has_xref(end_ea):
                if ida_bytes.is_func(end_ea):
                    #ida_kernwin.jumpto(end_ea)
                    ida_bytes.del_items(end_ea, 0, 1)
                    #insn = ida_ua.insn_t()
                    ida_funcs.del_func(end_ea)
            elif ida_bytes.has_xref(end_ea):
                ida_ua.create_insn(end_ea)
                ida_funcs.add_func(end_ea)
            else:
                print("!!! WTF !!! end_ea=" + hex(end_ea))
                
            #current_ea = idc.next_head(current_ea)
            
            if count % 500 == 0:
                print("count % 500 == 0! count=" + str(count)) #+ "/" + str(len(idautils.Functions)))
            
            count = count + 1

        Happy = True
        return count
    
    
def PLUGIN_ENTRY():

    intro()
    ida_kernwin.show_wait_box("Processing")
    
    try:
        print("Number functions fixed = " + str(fix_cleanup_funcs()))
    except Exception as e:
        print("WARNING: exception happened! str(e)=" + str(e))
        goto .bar_begin
    finally:
        if Happy == False:
            print(hex(ea) + ": " + str(name))
            print("WARNING: finally exit route from fix_cleanup.py!")
            ida_kernwin.hide_wait_box()
            return False
        else:
            print("SUCCESS: HAPPY fix_cleanup.py run!")
            ida_kernwin.hide_wait_box()
            return True
            
    print("!!! WTF !!!")
    return False