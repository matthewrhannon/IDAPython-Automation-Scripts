# PopPySig
# Author: sub1to

#from ida import *
import subprocess
import ida_name
import idautils
import idc
import idaapi
import ida_kernwin
import ida_ua

def is_a_function(ea):
    if not idc.isCode(idc.GetFlags(ea)):
        return False

    name = idc.get_func_name(ea)

    if name == "":
        return False

    start = idc.get_name_ea_simple(name)

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
    name = ida_name.get_ea_name(ea)
    i = 0
    while True:
        new_name = ida_name.get_ea_name(ea + i * 8)

        if new_name != name and new_name != "":
            break

        if idc.get_qword(ea) == 0:
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
        sig = "%s%02x " % (sig, idc.get_wide_byte(ea + i))
    return sig


def add_padding_to_sig(sig, count):
    for i in range(0, count):
        sig += "? "
    return sig


def add_instruction_to_sig(sig, ea):
    opcnt = op_count(ea)
    size = idaapi.get_item_end(ea) - ea
    offb = 0
    cmd = 0 #insn_t *
    #ida_ua.decode_insn(cmd, ea)
    #idaapi.decode_insn(cmd, ea)
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    for i in range(0, opcnt):
        if insn.ops[i].type == ida_ua.o_void:
            continue

        offb = insn.ops[i].offb

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
    ea = idc.get_screen_ea()

    if ea == BADADDR:
        print("Invalid cursor position")
        return

    res = create_pattern(ea)
    print(("%x: %s" % (ea, res)))

def scan(pattern):
    ea = idc.find_binary(0, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
    print(("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase())))

def fullscan(pattern):
    ea = 0
    while True:
        ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
        if ea == BADADDR:
            break
        print(("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase())))


def offset(o = None):
    if o is None:
        ea = idc.get_screen_ea()

        if ea == BADADDR:
            print("Invalid cursor position")
            return

        res = ea - idaapi.get_imagebase()
        copy2clip("%x" % res)
        print(("%x: +%x" % (ea, res)))
    else:
        print(("%x" % (idaapi.get_imagebase() + int(o, 16))))
        idaapi.jumpto(idaapi.get_imagebase() + int(o, 16))


addresses = {0x1439123E0,0x144058D27,0x1440432C0,0x144058DBC,0x144044438,0x1443C9E38,0x144058D25,0x140D7F810,0x14274F030,0x141C46400,0x142769B40,0x140E3CCD0,0x142749CB0,0X142769730,0x142749B70,0x1443C8948,0x142749D50,0x14274F5F0,0x140B39210,0x144058DC0,0x140B3D110,0x144058D3C,0x140B3E0A0,0x140B50060,0x140B3CFB0,0x140B3CEE0,0x144045708,0x140B50010,0x1440456F8,0x142769990,0x1440456F8,0x140D2C700,0x1443C8131,0x1443C83E1,0x1443C8531,0x1443C84C1,0x1443C8361,0x1443C8451,0x1443C85A1,0x1443C8051,0x1443C8131,0x143A897D8,0x143A0AB20,0x140218360,0x1443C82D8,0x140D0D040,0x14276EAC0,0x14276D190,0x140D0FD60,0x140C6AA40,0x1443C7DA0,0x1443C7E90,0x1443C7E10,0x1443C7CC0,0x1443C7C58,0x1443C7C50,0x1443C82F1,0x142766A40,0x142748B90,0x14274F240,0x140B483F0,0x1431BA740,0x1431B97D0,0x1458E0490,0x140D2A970,0x144058D38,0x145A920C0,0x143A0BFC1,0x140858200,0x140D12690,0x140D209F0,0x14068C0E0,0x1406580B0,0x144058DBC,0x1440432C0}
counter0 = -1

def run():
    global counter0

    for func in addresses:
        ea1 = func
        now = ea1

        ida_kernwin.jumpto(ea1)

        func_start = idc.get_func_attr(now, idc.FUNCATTR_START)
        func_end = idc.get_func_attr(now, idc.FUNCATTR_END)

        counter0 = counter0 + 1
        print(("Addresses[" + str(counter0) + "]=" + hex(func)))
        
        print((str(sig())))