import os
import sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

#__version__ = '2.0'
def initalize():
    print("ATTENTION: Started To Process idapythonrc.py script...\n")
    
    try:
        try:
            from ida_idaapi import idaapi
        except Exception:
            print("WARNING: NOTICE - from ida_idaapi import idaapi threw exception!")
            import idaapi
            pass
             
        try:
            import idc
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - idc!")
            pass
               
        try:
            import ida_ida
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - ida_ida!")
            pass

        try:
            import ida_nalt
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - ida_nalt!")
            pass

        try:
            import ida_kernwin
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - ida_kernwin!")
            pass
            
        try:
            #import QStringList
            from PyQt5 import QtGui, QtCore
            #from PyQt5 import *
            try:
                import PyQt5.QtCore
            except Exception:
                try:
                    import PyQt5
                except Exception:
                    pass
                finally:
                    print('DEBUG: PyQt5')
                pass
            finally:
                print('DEBUG: from PyQt5')
            #imort PyQt5.QtCore.QStringList
            #imort PyQt5.QtCore.QString
        except Exception:
            #print("WARNING: NOTICE - from idapythonrc - from PyQt5 import QtGui, QtCore!")
            #print("WARNING: NOTICE - from idapythonrc - from PyQt5 or PyQt5.QtCore.* import *!")     
            print("WARNING: NOTICE - from idapythonrc - from PyQt5.QtCore.* import *!")
            pass
        finally:
            print('from PyQt5 import QtGui, QtCore')

        # Add your favourite script to ScriptBox for easy access
        # scriptbox.appendscript("/here/is/my/favourite/script.py")

        # Uncomment if you want to set Python as default interpreter in IDA
        # import ida_idaapi
        idaapi.enable_extlang_python(True)

        # Disable the Python from interactive command-line
        # import ida_idaapi
        # ida_idaapi.enable_python_cli(False)

        # Set the timeout for the script execution cancel dialog
        #import ida_idaapi
        #idaapi.set_script_timeout(30)
        idaapi.set_script_timeout(300)
        
        # Get the current source code path
        source_path = [] 
        #idc.qstring[50] 
        #ida_nalt.get_srcdbg_paths()###
        #source_path = ida_nalt.get_srcdbg_paths()

        # Add the new source code path
        #source_path.append("D:/Users/Mat/AppData/Roaming/Hex-Rays/IDA Pro/plugins/ida_referee")
        #source_path.append("D:/Users/Mat/AppData/Roaming/Hex-Rays/IDA Pro/plugins/ida_medigate")
        source_path.append("C:/IDA/ida_medigate")

        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/conio")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/convert")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/dll")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/env")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/exec")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/filesystem")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/heap")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/inc")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/initializers")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/internal")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/locale")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/mbstring")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/misc")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/startup")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/stdio")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/stdlib")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/string")
        source_path.append("C:/Program Files/Windows Kits/10/Source/10.0.26100.0/ucrt/time")

        source_path.append("C:/Program Files/Windows Kits/10/Include/10.0.26100.0/shared")
        source_path.append("C:/Program Files/Windows Kits/10/Include/10.0.26100.0/ucrt")
        source_path.append("C:/Program Files/Windows Kits/10/Include/10.0.26100.0/um")

        source_path.append("C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/14.41.33901/crt/src/x64")
        source_path.append("C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/14.41.33901/crt/src/vcruntime")
        source_path.append("C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/14.41.33901/crt/src/vccorlib")
        source_path.append("C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/14.41.33901/crt/src/stl")
        source_path.append("C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/14.41.33901/crt/src/linkopts")
        source_path.append("C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/14.41.33901/crt/src/concrt")
        source_path.append("C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/14.41.33901/include")

        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sc2protocol-src/s2clientprotocol/sc2clientprotocol/s2clientprotocol/s2clientprotocol/s2clientprotocol/s2clientprotocol/s2clientprotocol")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/src/sc2api")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/src/sc2api/typeids")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/src/sc2utils")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/src/sc2lib")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/src/sc2renderer")

        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/util")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/util/internal")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/testing")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/testdata")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/stubs")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/io")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/compiler")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/protobuf-src/src/google/protobuf/compiler/cpp")

        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/civetweb-src/include")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/civetweb-src/src")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/civetweb-src/src/third_party")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/civetweb-src/src/third_party/lua-5.4.3/src")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/civetweb-src/src/third_party/duktape-1.8.0/src")

        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/include")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/atomic")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/audio/directsound")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/audio/wasapi")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/audio/winmm")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/audio")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/core/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/core")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/cpuinfo")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/dynapi")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/events")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/file")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/filesystem/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/filesystem")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/haptic/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/haptic")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/hidapi/hidapi")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/hidapi/pc")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/hidapi/windows/ddk_build")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/hidapi/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/hidapi")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/joystick/hidapi/steam")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/joystick/hidapi")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/joystick/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/joystick")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/libm")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/loadso/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/loadso")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/locale")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/locale/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/main/uikit")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/main/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/main")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/misc/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/misc")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/power/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/power")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/direct3d")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/direct3d11")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/direct3d12")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/opengl")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/opengles")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/opengles2")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/software")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/vitagxm/shader_src")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render/vitagxm")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/render")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/sensor/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/sensor")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/stdlib")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/test")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/thread/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/thread")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/timer/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/timer")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/video/windows")
        source_path.append("J:/sc2_example_map_hacks_bak_later_on/cpp-sc2_0/cpp-sc2/build/_deps/sdl-src/src/video")

        #My_String+=QString::number(a[i]
        #source_path = [] #idc.qstring[50] #ida_nalt.get_srcdbg_paths()
        #QString source_paths[]

        #i = 1
        #for stringy in source_path:
        #    sourcepaths[i] = str(stringy)
        #    i = i + 1

        # Save the source code path
        ida_nalt.set_srcdbg_paths(str(source_path))

        #import os
        #user = os.environ['USER']
        #user
        #    'miguel'

        current_IDA_PATH = os.environ['IDA']
        print("DEBUG: before - current_IDA_PATH=" + str(current_IDA_PATH))
        #import string
        current_IDA_PATH = current_IDA_PATH.replace('\\', '/')
        #result = current_IDA_PATH.replace("\\", "/")
        print("DEBUG: after - current_IDA_PATH=" + str(current_IDA_PATH))

        sys.path.append(str(current_IDA_PATH) + "/python")
        print("DEBUG: " + str(current_IDA_PATH) + "/python")

        #sys.path.append('D:/Users/Mat/AppData/Roaming/Hex-Rays/IDA Pro/plugins')
        
        #sys.path.append('D:/Users/Mat/AppData/Roaming/Hex-Rays/IDA Pro/plugins/ida_medigate')
        #sys.path.append('D:/Users/Mat/AppData/Roaming/Hex-Rays/IDA Pro/plugins/ida_referee')

        sys.path.append('C:/IDA/ida_medigate')
        #sys.path.append('D:/Users/Mat/AppData/Roaming/Hex-Rays/IDA Pro/plugins/ida_medigate')

        sys.path.append('I:/skinnyM/DESKTOP-5SPVSO8/Data/C/Users/skinnyM.DESKTOP-5SPVSO8/Desktop/IDA_v83/IDA_v83/python')

        sys.path.append('G:/Vector35/BinaryNinja/python')
        sys.path.append('G:/Vector35/BinaryNinja/python/binaryninja')

        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/ida_32')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/ida_64')

        sys.path.append('C:/IDA_Pro_8.3_Altered/python/flare')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/flare/ui')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/flare/ironstrings')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/flare/IDB_MSDN_Annotator')

        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/analysis')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/arch/x86')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/arch')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/core')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/expression')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/ir/translators')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/ir')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/jitter/loader')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/jitter')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/loader')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/miasm/runtime')

        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/core')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/analysis')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/cvt64')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/debugging')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/debugging/appcall')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/debugging/misc')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/debugging/dbghooks')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/hexrays')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/idbhooks')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/idphooks')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/pyqt')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/uihooks')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/forms')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/graphs')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/idaview')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/listings')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/misc')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/tabular_views/custom')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/tabular_views/string_window')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/examples/widgets/waitbox')

        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/findcrypt-yara')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/idabincat/bin')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/idabincat/conf')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/idabincat/hexview')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/idabincat/lib')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/idabincat')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/pybincat/tools')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/pybincat')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/pyphrank/containers')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/pyphrank/type_constructors')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/pyphrank')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/PyQt5/python_310')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/PyQt5/uic/Compiler')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/PyQt5/uic/Loader')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/PyQt5/uic/port_v3')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/PyQt5/uic/widget-plugins')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/PyQt5/uic')
        sys.path.append('C:/IDA_Pro_8.3_Altered/python/3/PyQt5')
        sys.path.append('C:/IDA_Pro_8.3_Altered/plugins/ret_sync_ext_ida')

        #!!!---Prepare-For-A-Disaster---!!!#

        try:
            import annotate_lineinfo
            annotate_lineinfo.ida_annotate_lineinfo()
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - ida_referee.ida_annotate_lineinfo!")
            pass   
        
        try:
            import ida_medigate.medigate_cpp_plugin
            doSomethingGood()
        except Exception:
            print("WARNING: either import ida_medigate.medigate_cpp_plugin or calling doSomethingGood threw an exception!")
            pass    
     
        try:
            from ida_ea import ea_main
            print("Attempted to launch ida_ea...")
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - ida_ea!")
            pass
            
        try:
            import zlib
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - zlib!")
            pass
            
        try:
            import traceback
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - traceback!")
            pass
            
        try:
            import webbrowser
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - webbrowser!")
            pass
            
        try:
            import datetime
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - datetime!")
            pass

        try:
            import numpy
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - numpy!")
            pass

        try:
            import string
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - string!")
            pass
        '''
            
        try:
            import objc2_analyzer
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - objc2_analyzer!")
            pass

        try:
            import apply_callee_type
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - apply_callee_type!")
            pass
            
        try:
            import objc2_xrefs_helper
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - objc2_xrefs_helper!")
            pass

        '''
        try:
            import shellcode_hash_search
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - shellcode_hash_search!")
            pass
            
        '''
        try:
            import shellcodechooser
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - shellcodechooser!")
            pass

        try:
            import struct_typer
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - struct_typer!")
            pass
            
        try:
            import stackstrings
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - stackstrings!")
            pass

        try:
            import argtracker
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - argtracker!")
            pass

        try:
            import jayutils
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - jayutils!")
            pass
            
        try:
            import idb2pat
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - idb2pat!")
            pass

        try:
            import code_grafter
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - code_grafter!")
            pass
            
        try:
            import annotate_IDB_MSDN
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - annotate_IDB_MSDN!")
            pass
            
        try:
            import IDB_MSDN_Annotator.__init__
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - import IDB_MSDN_Annotator.__init__!")
            pass

        try:
            import IDB_MSDN_Annotator.xml_parser
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - import IDB_MSDN_Annotator.xml_parser!")
            pass

        try:
            import ironstrings.ironstrings
            #import ironstrings.strings
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - ironstrings.ironstrings!")
            pass
            
        try:
            import seghelper
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - seghelper!")
            pass
        '''
        
        try:    
            import revil_string_decrypt
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - revil_string_decrypt!")
            pass
            
        ''' 

        try:
            import mrspicky
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - mrspicky!")
            pass
        try:
            import microavx
        except Exception:
            print("WARNING: NOTICE - from microavx SAD FACE")
            pass
        '''
        
        try:
            #from plugins import ea_main
            #import ea_main
            from ida_ea import ea_main
        except Exception:
            print("WARNING: ida_ea (from ida_ea import ea_main) not working... SAD FACE - 1 - from plugins import ea_main")
            pass
            
        try:
            import flare_emu
        except Exception:
            print("WARNING: NOTICE - from flare_emu!")
            pass

        try:
            import flare_emu_hooks
        except Exception:
            print("WARNING: NOTICE - from flare_emu_hooks!")
            pass

        try:
            import flare_emu_ida
        except Exception:
            print("WARNING: NOTICE - flare_emu_ida!")
            pass
        
        try:
            import ida_prefix
        except Exception:
            print("WARNING: NOTICE - from ida_prefix!")
            pass

        try:
            import idadeflat
        except Exception:
            print("WARNING: NOTICE - from idadeflat!")
            pass

        try:
            import LazyIDA
        except Exception:
            print("WARNING: NOTICE - from LazyIDA!")
            pass

        try:
            import SyncPlugin
        except Exception:
            print("WARNING: NOTICE - from SyncPlugin!")
            pass

        try:
            import vmx_intrinsics
        except Exception:
            print("WARNING: NOTICE - from vmx_intrinsics!")
            pass

        try:
            import idaref
        except Exception:
            print("WARNING: NOTICE - from idaref!")
            pass

        try:
            import gepetto
        except Exception:
            print("WARNING: NOTICE - from gepetto!")
            pass

        try:
            import VulChatGPT
        except Exception:
            print("WARNING: NOTICE - from VulChatGPT!")
            pass
            
        try:
            import hxtb_shell
        except Exception:
            print("WARNING: NOTICE - from hxtb_shell!")
            pass    
            
        try:
            import codemap
            print("DEBUG: import codemap went through good!")
        except Exception:
            print("WARNING: NOTICE - from codemap!")
            pass

        codemap = []
        try:
            codemap = codemap.Codemap()

            def IDA_State():
                if get_root_filename() is None:
                    return 'empty'
                try:
                    a = idc.GetRegValue('esp')
                    return 'running'
                except:
                    return 'static'


            # batch function break point script - daehee
            def Functions(start=None, end=None):
                if not start:
                    start = cvar.inf.minEA
                if not end:
                    end = cvar.inf.maxEA
                chunk = get_fchunk(start)
                if not chunk:
                    chunk = get_next_fchunk(start)
                while chunk and chunk.startEA < end and (chunk.flags & FUNC_TAIL) != 0:
                    chunk = get_next_fchunk(chunk.startEA)
                func = chunk
                while func and func.startEA < end:
                    yield (func)
                    func = get_next_func(func.startEA)


            def FuncItems(start):
                func = get_func(start)
                if not func:
                    return
                fii = func_item_iterator_t()
                ok = fii.set(func)
                while ok:
                    yield fii.current()
                    ok = fii.next_code()
            def Modules():
                mod = ida_idaapi.module_info_t()
                result = ida_idaapi.get_first_module(mod)
                while result:
                    yield ida_idaapi.object_t(name=mod.name, size=mod.size, base=mod.base, rebase_to=mod.rebase_to)
                    result = ida_idaapi.get_next_module(mod)


            # print slows IDA down
            class IDAHook(DBG_Hooks):
                global codemap

                def dbg_process_exit(self, pid, tid, ea, code):
                    codemap.db_insert()
                    codemap.init_codemap()
                    print(("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code)))

                def dbg_bpt(self, tid, ea):
                    if codemap.pause is True:
                        return 0    # stop visualizing

                    codemap.set_data()
                    codemap.db_insert_queue()
                    continue_process()                  # continue
                    return 0    # no warning


            def hook_ida():
                global debughook
                # Remove an existing debug hook
                try:
                    if debughook:
                        print("Removing previous hook ...")
                        debughook.unhook()
                except:
                    pass
                # Install the debug hook
                debughook = IDAHook()
                debughook.hook()
                debughook.steps = 0

            '''
            - SetRangeBP - 
            Get address range from user and setup bp to all instruction in that range.
            '''

            def SetRangeBP():
                if IDA_State() == 'empty':
                    print("no program loaded")
                    return
                start_addr = AskStr('', 'Start Addr? (e.g. 0x8000) : ')
                end_addr = AskStr('', 'End Addr? (e.g. 0xC000) : ')

                start_addr = int(start_addr.replace('0x', ''), 16)
                end_addr = int(end_addr.replace('0x', ''), 16)

                for e in Heads(start_addr, end_addr):
                    if get_bpt(e, bpt_t()) is False:
                        add_bpt(e, 0, BPT_SOFT)
                    else:
                        del_bpt(e)
            '''
            - SetFunctionBP - 
            put cursor inside the IDA-recognized function then call this. 
            bp will be set to all instructions of function
            '''

            def SetFunctionBP():
                if IDA_State() == 'empty':
                    print("no program loaded")
                    return
                ea = ScreenEA()
                target = 0
                for e in Functions():
                    if e.startEA <= ea and ea <= e.endEA:
                        target = e.startEA

                if target != 0:
                    for e in FuncItems(target):
                        if get_bpt(e, bpt_t()) is False:
                            add_bpt(e, 0, BPT_SOFT)
                        else:
                            del_bpt(e)
                else:
                    Warning('put cursor in the function body')


            '''
            - Start Trace -
            setup all bp's you want(maybe using GETBPLIST or SetFunctionBP or manually)
            then execute this script in order to create dygraph trace.
            '''

            def StartTracing():
                global codemap
                if codemap.start is False and IDA_State() != 'running':
                    print('IDA debugger not running')
                    return

                if codemap.start is True:
                    codemap.pause = not codemap.pause
                    print(("Codemap Paused" + str(codemap.pause)))
                    if codemap.pause is False:    # resume tracing
                        continue_process()
                    else:
                        codemap.db_insert()
                        suspend_process()
                    return

                # set current uid. if there is existing codemap instance, save it to prev_uids
                if codemap.uid != None:
                    codemap.prev_uids.append( codemap.uid )

                codemap.uid = datetime.datetime.fromtimestamp(
                    time.time()).strftime('%Y%m%d%H%M%S')
                
                
                codemap.init_arch()
                hook_ida()

                print("hook ida done.")
                print(("homedir: " + str(codemap.homedir)))
                print("making table...")
                # initialize sqlite3 db
                print((str(codemap.db_create())))

                # set default SQL
                if codemap.arch.name == 'x86':
                    codemap.query = "select eip from trace{0}".format(codemap.uid)
                if codemap.arch.name == 'x64':
                    codemap.query = "select rip from trace{0}".format(codemap.uid)
                
                print('start HTTP server')
                # start HTTP server
                codemap.start_webserver()

                # fire up chrome!
                result = 'http://{0}:{1}/{2}'.format(codemap.server,
                                                     codemap.port,
                                                     codemap.uid)
                webbrowser.open(result)
                print("start tracing...")
                codemap.start = True
                continue_process()


            '''
            - SaveModuleBP -
            open a dll file with IDA and execute this script after IDA analysis is done.
            the function offset information of dll will be saved to file inside Codemap directory
            '''

            def SaveModuleBP():
                global codemap
                try:
                    modname = AskStr('', 'module name : ')
                    bpo = ''
                    for e in Functions():
                        func = e.startEA
                        length = e.endEA - e.startEA
                        if length < codemap.func_min_size:
                            continue
                        offset = func - get_imagebase()
                        bpo += str(offset) + '/n'
                    print(("bp offset generation complete!" + str(len(bpo))))
                    payload = bpo
                    with open(codemap.homedir + modname + '.bpo', 'wb') as f:
                        f.write(zlib.compress(payload))
                except:
                    traceback.print_exc(file=sys.stdout)
                    

            '''
            - LoadModuleBP -
            while debugging the target app, put cursor somewhere inside the target module code. 
            execute the script and bp will be set for all functions specified in .bpo file
            '''

            def LoadModuleBP():
                global codemap
                try:
                    # get current cursor
                    cur = get_screen_ea()
                    baseaddr = 0
                    modname = ''
                    # what module is my cursor pointing?
                    for i in Modules():
                        if cur > i.base and cur < i.base + i.size:
                            modname = i.name.split('/x00')[0]
                            modname = modname.split('//')[-1:][0]
                            baseaddr = i.base

                    codemap.base = baseaddr         # this is needed.
                    modname = AskStr('', 'module name : ')
                    payload = ''
                    with open(codemap.homedir + modname + '.bpo', 'rb') as f:
                        payload = zlib.decompress(f.read())
                    bps = payload.split()
                    code = bytearray()
                    for bp in bps:
                        code += 'add_bpt({0}, 0, BPT_SOFT);'.format(baseaddr + int(bp))
                    print('setting breakpoints...')
                    # set bp!
                    exec(str(code))
                except:
                    traceback.print_exc(file=sys.stdout)

            def SetModuleBP():
                global codemap
                if codemap.start is False and IDA_State() == 'static':
                    SaveModuleBP()
                if codemap.start is False and IDA_State() == 'running':
                    LoadModuleBP()

            def ListenCodemap():
                global codemap
                codemap.start_websocketserver()
                print("Listning to codemap connection...")

            ida_expr.compile_idc_text	('static key_1() { RunPythonStatement("StartTracing()"); }')
            ida_expr.compile_idc_text	('static key_2() { RunPythonStatement("SetFunctionBP()"); }')
            ida_expr.compile_idc_text	('static key_3() { RunPythonStatement("SetRangeBP()"); }')
            ida_expr.compile_idc_text	('static key_4() { RunPythonStatement("SetModuleBP()"); }')
            ida_expr.compile_idc_text	('static key_5() { RunPythonStatement("ListenCodemap()"); }')

            ida_kernwin.append_idc_hotkey('Alt-1', 'key_1')
            ida_kernwin.append_idc_hotkey('Alt-2', 'key_2')
            ida_kernwin.append_idc_hotkey('Alt-3', 'key_3')
            ida_kernwin.append_idc_hotkey('Alt-4', 'key_4')
            ida_kernwin.append_idc_hotkey('Alt-5', 'key_5')

            print("ALT-1 : Start(Resume)/Pause Codemap")
            print("ALT-2 : Set Function BP")
            print("ALT-3 : Set Range BP")
            print("ALT-4 : Create/Setup Module BP")
            print("ALT-5 : Connect Codemap Graph with IDA")
            print("Codemap Python Plugin is ready. enjoy. - by daehee")
        except Exception:
            print("WARNING: NOTICE - from idapythonrc - codemap!")
            pass
    except:
        print("ERROR: idapythonrc.py - something went wrong!")
    finally:
        print("ATTENTION: !!! Finished Processing idapythonrc.py script !!!")
    
def PLUGIN_ENTRY():
    initalize()

if __name__ == "__main__":
    PLUGIN_ENTRY()