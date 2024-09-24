import ida_bytes
import idautils
import ida_idaapi
import ida_kernwin  # Import ida_kernwin for get_screen_ea
import ida_ua
import ida_auto
import ida_ida  # Import ida_ida for inf_get_max_ea

def find_and_reanalyze(ea):
    try:
        # Get the current instruction
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            return False

        target_ea = None
        for op in insn.ops:
            if op.type == ida_ua.o_imm:
                target_ea = op.value
                break

        if target_ea is None:
            return False

        # Check if the target address is already disassembled
        if ida_bytes.is_code(ida_bytes.get_flags(target_ea)):
            # Backup the original bytes before undefining
            original_bytes = ida_bytes.get_bytes(target_ea, ida_ua.get_item_size(target_ea))

            # Undefine the target address and attempt to create new assembly
            print(f"Found possible hit @ {hex(target_ea)}")
            ida_bytes.del_items(target_ea, ida_bytes.DELIT_SIMPLE)
            ida_auto.auto_make_code(target_ea)

            # Check if valid assembly was created
            if not ida_bytes.is_code(ida_bytes.get_flags(target_ea)):
                # Restore the original bytes and undo the undefine
                print(f"False path... at {hex(target_ea)}")
                ida_bytes.patch_bytes(target_ea, original_bytes)
                return False
            else:
                print(f"Reanalyzed instruction at 0x{target_ea:X}")

        return True

    except Exception as e:
        print(f"Error processing instruction at 0x{ea:X}: {str(e)}")
        return False

def main():
    # Get the current address using ida_kernwin.get_screen_ea()
    current_ea = ida_kernwin.get_screen_ea()

    # Get the maximum analyzed address in the database using ida_ida.inf_get_max_ea()
    max_ea = ida_ida.inf_get_max_ea()

    # Loop through the instructions
    while current_ea < max_ea and current_ea != ida_idaapi.BADADDR:
        if find_and_reanalyze(current_ea):
            print(f"Reanalyzed instruction at 0x{current_ea:X}")

        current_ea = ida_bytes.next_head(current_ea, max_ea)

if __name__ == '__main__':
    main()
