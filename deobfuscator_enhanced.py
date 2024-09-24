import idaapi
import ida_funcs
import ida_auto
import idc

global prev_curr_addr
prev_curr_addr = 0

def reanalyze_function(start_ea, end_ea):
    # Get the function at the specified address
    func = ida_funcs.get_func(start_ea)
    
    if func is None:
        print(f"No function found at {start_ea:#x}.")
        return

    print(f"Found function at {start_ea:#x}. Proceeding with reanalysis.")

    # Backup the original function's boundaries
    orig_start_ea = func.start_ea
    orig_end_ea = func.end_ea

    # Delete the existing function
    if ida_funcs.del_func(start_ea):
        print(f"Function at {start_ea:#x} deleted.")
    else:
        print(f"Failed to delete function at {start_ea:#x}.")
        return

    # Attempt to re-create the function with the specified boundaries
    if ida_funcs.add_func(start_ea, end_ea):
        print(f"Function re-created at {start_ea:#x} to {end_ea:#x}.")
    else:
        print(f"Failed to re-create function at {start_ea:#x} to {end_ea:#x}. Rolling back.")

        # If function re-creation fails, attempt to restore the original function
        if ida_funcs.add_func(orig_start_ea, orig_end_ea):
            print(f"Original function restored at {orig_start_ea:#x} to {orig_end_ea:#x}.")
        else:
            print(f"Failed to manually restore the original function at {orig_start_ea:#x} to {orig_end_ea:#x}.")
            # Fallback to undo operation using revert_database
            print("Attempting to revert the database to undo recent changes.")
            if idaapi.revert_database(1):
                print("Database reverted successfully. The original function is restored.")
            else:
                print("Failed to revert the database. Manual restoration may be required.")
        return

    # Force code creation and re-analysis
    ida_auto.auto_make_code(start_ea)
    ida_auto.auto_make_proc(start_ea)

    print(f"Reanalysis of the function from {start_ea:#x} to {end_ea:#x} completed.")

def run():
    global prev_curr_addr
    
    now = here()
    print('[+] CurPos: ' + hex(now))
    cur_func = get_name_ea_simple(get_func_name(here()))
    print('[+] CurFunc: ' + hex(cur_func))
    func_start = idc.get_func_attr(now, FUNCATTR_START)
    func_end = idc.get_func_attr(now, FUNCATTR_END)
    print('[+] FuncStart: ' + hex(func_start))
    print('[+] FuncEnd: ' + hex(func_end))

    #prev_curr_addr = 0

    curr_addr = func_start
    while curr_addr < func_end:
        disasm = generate_disasm_line(curr_addr, 1)
        print(hex(curr_addr) + '\t' + disasm)

        is_obfuscated = False

        # Enhanced Obfuscation Detection Patterns
        if 'short near ptr' in disasm:
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if 'nop' not in next_disasm:
                if disasm[0] == 'j':
                    is_obfuscated = True
                elif 'call' in disasm:  # Detect call-based obfuscation
                    is_obfuscated = True
        elif ', cs:dword' in disasm:
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if 'add' in next_disasm:
                next_disasm = generate_disasm_line(next_head(next_head(next_head(curr_addr))), 1)
                if 'cmp' in next_disasm:
                    start_addr = curr_addr
                    end_addr = 0
                    while end_addr == 0:
                        disasm = generate_disasm_line(start_addr, 1)
                        print(hex(start_addr) + ' - ' + disasm)
                        if ('short' in disasm) and (disasm[0] == 'j'):
                            end_addr = start_addr
                            break
                        start_addr = next_head(start_addr)
                    if end_addr:
                        for i in range(curr_addr, end_addr):
                            idc.patch_byte(i, 0x90)
                        curr_addr = end_addr
                        is_obfuscated = True
        elif 'jz' in disasm:
            prev_disasm = generate_disasm_line(prev_head(curr_addr), 1)
            next_disasm = generate_disasm_line(next_head(curr_addr), 1)
            if 'nop' not in next_disasm:
                if 'cmp' in prev_disasm:
                    if get_operand_value(prev_head(curr_addr), 1) == 0xE8:
                        is_obfuscated = True
        elif 'test' in disasm and 'jz' in disasm:  # Detect simple opaque predicates
            is_obfuscated = True
        elif 'xor' in disasm and 'jz' in disasm:  # Detect more complex opaque predicates
            is_obfuscated = True
        elif 'mov' in disasm and 'jz' in disasm:  # Detect opaque predicates with mov
            is_obfuscated = True
        elif 'cmp' in disasm and 'jz' in disasm:  # Detect opaque predicates with cmp
            is_obfuscated = True
        elif 'push' in disasm and 'jz' in disasm:  # Detect opaque predicates with push
            is_obfuscated = True
        elif 'pop' in disasm and 'jz' in disasm:  # Detect opaque predicates with pop
            is_obfuscated = True
        elif 'add' in disasm and 'jz' in disasm:  # Detect opaque predicates with add
            is_obfuscated = True
        elif 'sub' in disasm and 'jz' in disasm:  # Detect opaque predicates with sub
            is_obfuscated = True
        elif 'and' in disasm and 'jz' in disasm:  # Detect opaque predicates with and
            is_obfuscated = True
        elif 'or' in disasm and 'jz' in disasm:  # Detect opaque predicates with or
            is_obfuscated = True
        elif 'not' in disasm and 'jz' in disasm:  # Detect opaque predicates with not
            is_obfuscated = True
        elif 'neg' in disasm and 'jz' in disasm:  # Detect opaque predicates with neg
            is_obfuscated = True
        elif 'mul' in disasm and 'jz' in disasm:  # Detect opaque predicates with mul
            is_obfuscated = True
        elif 'div' in disasm and 'jz' in disasm:  # Detect opaque predicates with div
            is_obfuscated = True
        elif 'inc' in disasm and 'jz' in disasm:  # Detect opaque predicates with inc
            is_obfuscated = True
        elif 'dec' in disasm and 'jz' in disasm:  # Detect opaque predicates with dec
            is_obfuscated = True
        elif 'lea' in disasm and 'jz' in disasm:  # Detect opaque predicates with lea
            is_obfuscated = True
        elif 'xchg' in disasm and 'jz' in disasm:  # Detect opaque predicates with xchg
            is_obfuscated = True
        elif 'jmp' in disasm and 'jz' in disasm:  # Detect opaque predicates with jmp
            is_obfuscated = True
        elif 'call' in disasm and 'jz' in disasm:  # Detect opaque predicates with call
            is_obfuscated = True
        elif 'ret' in disasm and 'jz' in disasm:  # Detect opaque predicates with ret
            is_obfuscated = True
        elif 'int' in disasm and 'jz' in disasm:  # Detect opaque predicates with int
            is_obfuscated = True
        elif 'loop' in disasm and 'jz' in disasm:  # Detect opaque predicates with loop
            is_obfuscated = True
        elif 'jcxz' in disasm and 'jz' in disasm:  # Detect opaque predicates with jcxz
            is_obfuscated = True
        elif 'jecxz' in disasm and 'jz' in disasm:  # Detect opaque predicates with jecxz
            is_obfuscated = True
        elif 'jmp' in disasm and 'j' in disasm:  # Detect simple control flow flattening
            is_obfuscated = True
        elif 'call' in disasm and 'j' in disasm:  # Detect control flow flattening with call
            is_obfuscated = True
        elif 'ret' in disasm and 'j' in disasm:  # Detect control flow flattening with ret
            is_obfuscated = True
        elif 'int' in disasm and 'j' in disasm:  # Detect control flow flattening with int
            is_obfuscated = True
        elif 'loop' in disasm and 'j' in disasm:  # Detect control flow flattening with loop
            is_obfuscated = True
        elif 'jcxz' in disasm and 'j' in disasm:  # Detect control flow flattening with jcxz
            is_obfuscated = True
        elif 'jecxz' in disasm and 'j' in disasm:  # Detect control flow flattening with jecxz
            is_obfuscated = True

        if is_obfuscated:
            # Improved Jump Address Handling
            jmp_addr = get_operand_value(curr_addr, 0)
            #if jmp_addr == 0:  # Handle cases where jmp address is not resolved
            #    print('[!] Found obfuscated jmp at ' + hex(curr_addr) + ' but destination is unresolved.')
            #    continue
                
            #jmp_next = next_head(jmp_addr)
            print('[!] Found obfuscated jmp at ' + hex(curr_addr) + ' to ' + hex(jmp_addr))
            
            for i in range(curr_addr, jmp_addr):
                
                idc.patch_byte(i, 0x90)
                
                #prev_curr_addr = curr_addr
                #curr_addr = jmp_addr  # Update curr_addr to the jump destination
            
                #if prev_curr_addr == curr_addr:
                #    print('\n\n\n!!! 1 - Caught double address!!!\n\n\n')
                    #reanalyze_function(func_start, func_end)  # Replace with actual addresses
            break
            reanalyze_function(func_start, func_end)  # Replace with actual addresses
            #continue
                
        prev_curr_addr = curr_addr
        curr_addr = next_head(curr_addr)
        
        if hex(prev_curr_addr) == hex(curr_addr):
            print('!!! 2 - Caught double address!!! prev_curr_addr=' + hex(prev_curr_addr) + 'hex(curr_addr)=' + hex(curr_addr))
            #reanalyze_function(func_start, func_end)  # Replace with actual addresses
        
        
        #continue
        
idaapi.compile_idc_text('static fn1() { RunPythonStatement("run()"); }')

add_idc_hotkey("F1", 'fn1')
#jim the wonder the dog