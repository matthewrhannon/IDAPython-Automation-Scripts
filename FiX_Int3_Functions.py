import concurrent.futures

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
import numpy as np

thread_num = -1
func_arrays = []

def intro():

    info = idaapi.get_inf_structure()
    filename = idaapi.get_input_file_path()
    entrypoint = info.start_ip
    imagebase = ida_nalt.get_imagebase()
    is_64bits = info.is_64bit()
    is_dll = info.is_dll()
    proc_name = ida_ida.inf_get_procname()
    
    print("info=" + str(info))
    print("filename=" + str(filename))    
    print("entrypoint=" + hex(entrypoint))
    print("imagebase=" + hex(imagebase))
    print("is_64bits=" + str(is_64bits))
    print("is_dll=" + str(is_dll))
    print("proc_name=" + str(proc_name))
    
    return True
    
def getInstructionBytes(offset):
        ins = idautils.DecodeInstruction(offset)
        ins_bytes = ida_bytes.get_bytes(offset, ins.size)
        return ins_bytes 

def remake_single_funcs():

    FUNCATTR_STARTY = 0x1401183D0
    FUNCATTR_ENDY = 0x14011841A

    #current_ea = 0
    count = 0
    dont_do_again = False
    for function_ea in idautils.Functions():
        dont_do_again = True
        
        if not dont_do_again:
            
            start_ea = idc.get_func_attr(function_ea, FUNCATTR_STARTY) #0x0000000141D99590 
            end_ea = idc.get_func_attr(function_ea, FUNCATTR_ENDY) #0x0000000141D9CD2C 
            
            func_length = end_ea - start_ea
           
            #current_ea = start_ea
            
            print("start_ea=" + hex(start_ea) + " --> end_ea=" + hex(end_ea) + " size=" + str(func_length))
            
            #start_ea = idc.to_ea(start_ea)
            ida_kernwin.jumpto(start_ea)
            
            #Save Function Comments
            function_disassembly_comments_Repeat = 1
            function_disassembly_comments = ''
            function_disassembly_comments = idc.get_func_cmt(start_ea, 1)
            if function_disassembly_comments == '' or str(''):
                function_disassembly_comments = idc.get_func_cmt(start_ea, 0)
                if function_disassembly_comments == '' or str(''):
                    function_disassembly_comments = ''
                    function_disassembly_comments_Repeat = 0
                   
            #Save Disassembly Comments
            disassembly_comments_Repeat = 1
            disassembly_comments = ''
            disassembly_comments = idc.get_cmt(start_ea, 1)
            if disassembly_comments == '' or str(''):
                disassembly_comments = idc.get_cmt(start_ea, 0)
                if disassembly_comments == '' or str(''):
                    disassembly_comments = ''
                    disassembly_comments_Repeat = 0

            #TODO: hexrays_comments
            #TODO: epilogue and 'postlog'
            
            #sanitycheck
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
            idc.set_func_cmt(start_ea, function_disassembly_comments, function_disassembly_comments_Repeat)
            idc.set_cmt(start_ea, disassembly_comments, disassembly_comments_Repeat)
            
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
                
            #ida_funcs.update_func(1)
            #current_ea = idc.next_head(current_ea)
            
            count = count + 1
            if count % 500 == 0:
                print("count % 500 == 0! count=" + str(count)) #+ "/" + str(len(idautils.Functions)))
                #return count
            
        return count
        
def remake_all_funcs():

    #current_ea = 0
    count = 0
    for function_ea in idautils.Functions():
        start_ea = idc.get_func_attr(function_ea, idc.FUNCATTR_START) #0x0000000141D99590 
        end_ea = idc.get_func_attr(function_ea, idc.FUNCATTR_END) #0x0000000141D9CD2C 
        
        func_length = end_ea - start_ea
       
        #current_ea = start_ea
        
        print("start_ea=" + hex(start_ea) + " --> end_ea=" + hex(end_ea) + " size=" + str(func_length))
        
        #start_ea = idc.to_ea(start_ea)
        ida_kernwin.jumpto(start_ea)
        
        #Save Function Comments
        function_disassembly_comments_Repeat = 1
        function_disassembly_comments = ''
        function_disassembly_comments = idc.get_func_cmt(start_ea, 1)
        if function_disassembly_comments == '' or str(''):
            function_disassembly_comments = idc.get_func_cmt(start_ea, 0)
            if function_disassembly_comments == '' or str(''):
                function_disassembly_comments = ''
                function_disassembly_comments_Repeat = 0
               
        #Save Disassembly Comments
        disassembly_comments_Repeat = 1
        disassembly_comments = ''
        disassembly_comments = idc.get_cmt(start_ea, 1)
        if disassembly_comments == '' or str(''):
            disassembly_comments = idc.get_cmt(start_ea, 0)
            if disassembly_comments == '' or str(''):
                disassembly_comments = ''
                disassembly_comments_Repeat = 0
        
        
        #TODO: hexrays_comments
        #TODO: epilogue and 'postlog'
        
        #sanitycheck
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
        idc.set_func_cmt(start_ea, function_disassembly_comments, function_disassembly_comments_Repeat)
        idc.set_cmt(start_ea, disassembly_comments, disassembly_comments_Repeat)
        
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
            
        #ida_funcs.update_func(1)
        #current_ea = idc.next_head(current_ea)
        
        
        count = count + 1
        if count % 500 == 0:
            print("count % 500 == 0! count=" + str(count)) #+ "/" + str(len(idautils.Functions)))
            #return count
        
    return count

countera = 0
def remake_some_funcs():

    global thread_num
    thread_num = thread_num + 1
    print("thread_num=" + str(thread_num))
    
    #current_ea = 0
    count = 0
    #for function_ea in idautils.Functions():
    for function_ea in func_arrays[thread_num]:
        start_ea = idc.get_func_attr(function_ea, idc.FUNCATTR_START) #0x0000000141D99590 
        end_ea = idc.get_func_attr(function_ea, idc.FUNCATTR_END) #0x0000000141D9CD2C 
        
        func_length = end_ea - start_ea
       
        #current_ea = start_ea
        
        print("start_ea=" + hex(start_ea) + " --> end_ea=" + hex(end_ea) + " size=" + str(func_length))
        
        #start_ea = idc.to_ea(start_ea)
        ida_kernwin.jumpto(start_ea)
        '''
        #Save Function Comments
        function_disassembly_comments_Repeat = 1
        function_disassembly_comments = ''
        function_disassembly_comments = idc.get_func_cmt(start_ea, 1)
        if function_disassembly_comments == '' or str(''):
            function_disassembly_comments = idc.get_func_cmt(start_ea, 0)
            if function_disassembly_comments == '' or str(''):
                function_disassembly_comments = ''
                function_disassembly_comments_Repeat = 0
               
        #Save Disassembly Comments
        disassembly_comments_Repeat = 1
        disassembly_comments = ''
        disassembly_comments = idc.get_cmt(start_ea, 1)
        if disassembly_comments == '' or str(''):
            disassembly_comments = idc.get_cmt(start_ea, 0)
            if disassembly_comments == '' or str(''):
                disassembly_comments = ''
                disassembly_comments_Repeat = 0
        '''
        
        #TODO: hexrays_comments
        #TODO: epilogue and 'postlog'
        
        #sanitycheck
        if start_ea % 0x04 != 0:
            print("[SANITY FAILURE] start_ea=" + hex(start_ea)+ " and end_ea=" + hex(end_ea) + "... continuing ... and destroying instructions inbetween...")
            num_bytes_to_un_encode = func_length
            
            ida_funcs.del_func(start_ea)
            ida_bytes.del_items(start_ea, 0, num_bytes_to_un_encode)
            
            count = count + 1        
            if count % 500 == 0:
                print("count % 500 == 0! count=" + str(count)) #+ "/" + str(len(idautils.Functions)))
                
            continue
            
        else:
            continue
        #ida_funcs.del_func(function_ea)
        #ida_ua.create_insn(insn, start_ea)
'''
        ida_funcs.del_func(function_ea)
        ida_ua.create_insn(start_ea)
        ida_funcs.add_func(start_ea)
        idc.set_func_cmt(start_ea, function_disassembly_comments, function_disassembly_comments_Repeat)
        idc.set_cmt(start_ea, disassembly_comments, disassembly_comments_Repeat)
        
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
            
        #ida_funcs.update_func(1)
        #current_ea = idc.next_head(current_ea)
'''

# Yield successive n-sized
# chunks from l.
def divide_chunks(l, n):
    
    # looping till length l
    global countera
    for i in range(0, countera, n): 
        yield l[i:i + n]


def PLUGIN_ENTRY():
    intro()


    counter1 = 0
    
    funcs = idautils.Functions()
    for func_count in funcs:
        counter1 = counter1 + 1
    num_functions = counter1 #int(len(funcs), 10)
    print("num_functions=" + str(num_functions))
    
    num_threads = 8
    #thread_size = int(num_functions / num_threads, 10)
    thread_size = num_functions // num_threads
    print("thread_size=" + str(thread_size))
    n = thread_size
    #thread_size_remainder = num_functions % num_threads
    func_arrays = list(divide_chunks(funcs, thread_size))
    #func_arrays = [funcs[i * n:(i + 1) * n] for i in range(int((counter1 + n - 1) / n ))]
    #for i in np.arange(c/10):
    
    #print(str(func_arrays))
    
    print("Main thread continuing to run...")
    
    def worker():
        remake_some_funcs()
     
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads)
    
    counter = 0
    print("Launching...")
    while counter < num_threads:
        pool.submit(worker)
        counter = counter + 1
        
    pool.shutdown(wait=True)
     
    print("Done!")
    
    
    
'''    
 def PLUGIN_ENTRY():
    intro()   
    print("Number functions remade = " + str(remake_all_funcs()))
'''