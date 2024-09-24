import idaapi
import idautils
import ida_kernwin
import ida_search
import ida_bytes
# PopPySig
# Author: sub1to

from ida import *
import subprocess

def op_count(ea):
    '''Return the number of operands of given instruction'''
    length = idaapi.decode_insn(idaapi.insn_t(), ea)
    for c,v in enumerate(idaapi.insn_t().ops):
        if v.type == idaapi.o_void:
            return c
        continue
    # maximum operand count. ida might be wrong here...
    return c

def copy2clip(txt):
    cmd='echo|set /p="'+txt.strip()+'"|clip'
    return subprocess.check_call(cmd, shell=True)

def is_a_function(ea):
    if not idc.isCode(idc.GetFlags(ea)):
        return False

    name = idc.GetFunctionName(ea)

    if name == "":
        return False	

    start = idc.LocByName(name)

    if start == BADADDR or start != ea:
        return False

    #substr
    name = name[0: 7]

    if name == "nullsub":
        return False

    name = name[0: 6]

    if name == "NATIVE":
        return False

    return True


def find_vtable_length(ea):
    name = idc.GetTrueName(ea)
    i = 0
    while True:
        new_name = idc.GetTrueName(ea + i * 8)

        if new_name != name and new_name != "":
            break

        if idc.Qword(ea) == 0:
            break

        i += 1

    return i - 1


def is_pattern_unique(pattern):
    ea = idc.find_binary(0, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)

    if ea == BADADDR:
        return -1

    if idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern) != BADADDR:
        return 0

    return 1


def add_bytes_to_sig(sig, ea, count):
    for i in range(0, count):
        sig = "%s%02x " % (sig, idaapi.get_byte(ea + i))
    return sig


def add_padding_to_sig(sig, count):
    for i in range(0, count):
        sig += "? "
    return sig


def add_instruction_to_sig(sig, ea):
    opcnt = op_count(ea)
    size = idaapi.get_item_end(ea) - ea
    offb = 0

    idaapi.decode_insn(idaapi.insn_t(), ea)
    for i in range(0, opcnt):
        if idaapi.insn_t().ops[i].type == idaapi.o_void:
            continue

        offb = idaapi.insn_t().ops[i].offb

        if offb > 0:
            break

    if offb == 0:
        sig = add_bytes_to_sig(sig, ea, size)
        return sig, ea + size

    sig = add_bytes_to_sig(sig, ea, offb)
    sig = add_padding_to_sig(sig, size - offb)

    return sig, ea + size


def create_pattern(ea):
    sig = ""
    sig, ea = add_instruction_to_sig(sig, ea)

    while not is_pattern_unique(sig):
        sig, ea = add_instruction_to_sig(sig, ea)

    while sig[-1] == ' ' or sig[-1] == '?':
        sig = sig[:-1]

    return sig

def sig():
    ea = idc.get_screen_ea() #idc.ScreenEA()

    if ea == BADADDR:
        print("Invalid cursor position")
        return

    res = create_pattern(ea)
    copy2clip(res)
    print("%x: %s" % (ea, res))

def scan(pattern):
    ea = idc.find_binary(0, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
    print("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase()))

def fullscan(pattern):
    ea = 0
    while True:
        ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
        if ea == BADADDR:
            break
        print("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase()))


def offset(o = None):
    if o is None:
        ea = idc.get_screen_ea() %idc.ScreenEA()

        if ea == BADADDR:
            print("Invalid cursor position")
            return

        res = ea - idaapi.get_imagebase()
        copy2clip("%x" % res)
        print("%x: +%x" % (ea, res))
    else:
        print("%x" % (idaapi.get_imagebase() + int(o, 16)))
        idaapi.jumpto(idaapi.get_imagebase() + int(o, 16))

def run():
    #funcs = idautils.Functions()
    funcs = idautils.Names()
    for func in funcs:
        ea1, name = func #func.here()
        now = ea1
        
        #print('[+] CurPos: ' + hex(now))
        #cur_func = idc.get_name_ea_simple(0, idc.get_func_name(func))
        cur_func = idc.get_name_ea_simple(name) #(func)
        str1 = str(name)
        isGoodFunc = str1.find('SC2_')
        if isGoodFunc != -1:
           ida_kernwin.jumpto(ea1)
           print('[+] CurFuncName: ' + str(name)) #str(idc.get_func_name(func)))
           #print('   [+]CurPos: ' + hex(now))
           print('   [+] CurFunc: ' + hex(cur_func))
           func_start = idc.get_func_attr(now, idc.FUNCATTR_START)
           func_end = idc.get_func_attr(now, idc.FUNCATTR_END)
           print('   [+] FuncStart: ' + hex(func_start))
           print('   [+] FuncEnd: ' + hex(func_end))

           print(str(sig()))

idaapi.compile_idc_text('static fn1() { RunPythonStatement("run()"); }')

add_idc_hotkey("F1", 'fn1')