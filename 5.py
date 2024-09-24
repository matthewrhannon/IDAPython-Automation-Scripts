
from idautils import *
from idc import *
from idaapi import *
import ida_segment

def getRange(ea):
    return get_segm_attr(ea, idc.SEGATTR_START), get_segm_attr(ea, idc.SEGATTR_END)

def fix_overlapping_sections():
    # Get the list of segments
    segments = Segments()

    # Iterate over the segments
    for seg_start in segments:
        seg_start, seg_end = getRange(seg_start)
        #seg_end = get_segm_attr(hex(seg_start), SEGATTR_END)

        # Get the segment name
        for ea in idautils.Segments():
            segm = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(segm)

        #seg_name = get_segm_name(seg_start)

        # Check if the segment is a text or data segment
        if True:
            # Get the list of subsections in the segment
            subsections = 0


            #subsections = SubSections(seg_start, seg_end)

            # Iterate over the subsections
            for ea in Segments():
                sub_start, sub_end = getRange(ea)
            #for sub_start, sub_end in subsections:
                # Get the subsection name
                segm = ida_segment.getseg(sub_start)
                sub_name = ida_segment.get_segm_name(segm)
                #sub_name = get_segm_name(sub_start)

                # Check if the subsection overlaps with other subsections
                if here() < get_segm_attr(ea, idc.SEGATTR_END): #sub_end:
                    print(f"Overlapping subsection found: {sub_name} ({hex(sub_start)} - {hex(sub_end)})")

                    # Backup the original bytes before undefining
                    original_bytes = get_bytes(sub_start, sub_end - sub_start)

                    # Undefine the subsection
                    del_items(sub_start, 1)

                    # Redefine the subsection as code
                    auto_make_code(sub_start)

                    # Check if valid assembly was created
                    new_insn = DecodeInstruction(sub_start)
                    if new_insn is None:
                        # Restore the original bytes and undo the undefine
                        print("Failed to create valid assembly, restoring original bytes...")
                        auto_make_code(sub_start)
                        #undo()
                    else:
                        print("Valid assembly created successfully.")

# Call the function to fix overlapping sections
fix_overlapping_sections()