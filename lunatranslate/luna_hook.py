import os
import ctypes
import struct
import sys
from ctypes import (
    Structure, WINFUNCTYPE, POINTER, c_uint, c_uint32, c_uint64,
    c_int, c_bool, c_void_p, c_wchar_p, c_char_p, sizeof, byref, c_size_t,
    create_string_buffer, windll, c_byte, c_wchar
)

DWORD = c_uint32
LPCWSTR = c_wchar_p
HANDLE = c_void_p


PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

class ThreadParam(Structure):
    _fields_ = [
        ("processId", c_uint),
        ("addr", c_uint64),
        ("ctx", c_uint64),
        ("ctx2", c_uint64),
    ]

FindHooksCallback_t = WINFUNCTYPE(None, c_wchar_p, c_wchar_p)
ProcessEvent = WINFUNCTYPE(None, DWORD)
ThreadEvent_maybeEmbed = WINFUNCTYPE(None, c_wchar_p, c_char_p, ThreadParam, c_bool)
ThreadEvent = WINFUNCTYPE(None, c_wchar_p, c_char_p, ThreadParam)
OutputCallback = WINFUNCTYPE(None, c_wchar_p, c_char_p, ThreadParam, c_wchar_p)
HostInfoHandler = WINFUNCTYPE(None, c_int, c_wchar_p)
HookInsertHandler = WINFUNCTYPE(None, DWORD, c_uint64, c_wchar_p)
EmbedCallback = WINFUNCTYPE(None, c_wchar_p, ThreadParam)
QueryHistoryCallback = WINFUNCTYPE(None, c_wchar_p)
I18NQueryCallback = WINFUNCTYPE(c_void_p, c_wchar_p)

class MODULEENTRY32W(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", POINTER(c_byte)),
        ("modBaseSize", DWORD),
        ("hModule", c_void_p),
        ("szModule", c_wchar * 256),
        ("szExePath", c_wchar * 260),
    ]

def _is_process_64bit(pid: int) -> bool:
    kernel32 = ctypes.windll.kernel32
    h = kernel32.OpenProcess(0x1000, False, pid)
    if not h: return False
    is_wow64 = c_bool(False)
    rv = kernel32.IsWow64Process(h, byref(is_wow64))
    kernel32.CloseHandle(h)
    if not rv: return False
    return not is_wow64.value

def get_remote_module_handle(pid, module_name, target_32bit=False):
    kernel32 = windll.kernel32
    hModuleSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    
    if hModuleSnap == -1: return None

    me32 = MODULEENTRY32W()
    me32.dwSize = sizeof(MODULEENTRY32W)

    if not kernel32.Module32FirstW(hModuleSnap, byref(me32)):
        kernel32.CloseHandle(hModuleSnap)
        return None

    found_handle = None
    debug_candidates = []
    
    while True:
        name = me32.szModule.lower()
        if name == module_name.lower():
            base_addr = ctypes.cast(me32.modBaseAddr, c_void_p).value or 0
            debug_candidates.append(hex(base_addr))
            
            if target_32bit:
                if base_addr < 0xFFFFFFFF:
                    found_handle = base_addr
                    break
            else:
                found_handle = base_addr
                break
                
        if not kernel32.Module32NextW(hModuleSnap, byref(me32)):
            break

    kernel32.CloseHandle(hModuleSnap)
    
    if not found_handle and debug_candidates:
        print(f"[LunaHook] Found {module_name} candidates but filtered out: {debug_candidates}")
        
    return found_handle

def get_remote_proc_address(h_process, module_base, func_name):
    kernel32 = windll.kernel32
    
    def read_mem(addr, length):
        buf = create_string_buffer(length)
        read = c_size_t()
        kernel32.ReadProcessMemory(h_process, c_void_p(addr), buf, length, byref(read))
        return buf.raw

    base_addr = module_base
    if not base_addr: return None

    dos_header = read_mem(base_addr, 64)
    if dos_header[:2] != b'MZ': return None
    e_lfanew = struct.unpack('<I', dos_header[60:64])[0]

    pe_base = base_addr + e_lfanew
    export_dir_rva_mem = read_mem(pe_base + 120, 4) 
    export_dir_rva = struct.unpack('<I', export_dir_rva_mem)[0]
    
    if export_dir_rva == 0: return None

    export_dir_addr = base_addr + export_dir_rva
    export_dir_data = read_mem(export_dir_addr, 40)
    
    rv_funcs, rv_names, rv_ords = struct.unpack('<III', export_dir_data[28:40])
    addr_funcs = base_addr + rv_funcs
    addr_names = base_addr + rv_names
    addr_ords = base_addr + rv_ords

    num_names = struct.unpack('<I', export_dir_data[24:28])[0]
    target_name = func_name.encode('ascii')
    
    for i in range(min(num_names, 4000)):
        name_rva = struct.unpack('<I', read_mem(addr_names + i*4, 4))[0]
        func_name_mem = read_mem(base_addr + name_rva, 64)
        fname = func_name_mem.split(b'\0')[0]
        
        if fname == target_name:
            ordinal = struct.unpack('<H', read_mem(addr_ords + i*2, 2))[0]
            func_rva = struct.unpack('<I', read_mem(addr_funcs + ordinal*4, 4))[0]
            return base_addr + func_rva

    return None

class LunaHook:
    def __init__(self) -> None:
        base = os.path.dirname(__file__)
        self._base = base
        self._files_dir = os.path.join(base, "files")
        self._hook_dir = os.path.join(self._files_dir, "LunaHook")
        self._host_path = os.path.join(self._hook_dir, "LunaHost64.dll")
        
        if not os.path.exists(self._host_path):
            raise FileNotFoundError(f"[LunaHook] LunaHost64.dll not found: {self._host_path}")

        print("[LunaHook] Loading host DLL:", self._host_path)
        self._host = ctypes.CDLL(self._host_path)
        self._keeprefs = []
        self._output_handler = None
        self._init_host_functions()

    def _init_host_functions(self):
        self.Luna_Start = self._host.Luna_Start
        self.Luna_Start.restype = c_bool
        self.Luna_Start.argtypes = (
            ProcessEvent, ProcessEvent, ThreadEvent_maybeEmbed, ThreadEvent,
            OutputCallback, HostInfoHandler, HookInsertHandler, EmbedCallback, I18NQueryCallback,
        )
        self.Luna_ConnectProcess = self._host.Luna_ConnectProcess
        self.Luna_ConnectProcess.argtypes = (DWORD,); self.Luna_ConnectProcess.restype = c_bool
        self.Luna_CheckIfNeedInject = self._host.Luna_CheckIfNeedInject
        self.Luna_CheckIfNeedInject.argtypes = (DWORD,); self.Luna_CheckIfNeedInject.restype = c_bool
        self.Luna_InsertPCHooks = self._host.Luna_InsertPCHooks
        self.Luna_InsertPCHooks.argtypes = (DWORD, c_int); self.Luna_InsertPCHooks.restype = c_bool
        self.Luna_ResetLang = getattr(self._host, "Luna_ResetLang", None)

    def _handle_output_safe(self, hc, hn, tp, output):
        try:
            if output and self._output_handler: 
                self._output_handler(output)
        except Exception:
            pass

    def _injectdll(self, pids, arch: str):
        dll_name = f"LunaHook{arch}.dll"
        dll_path = os.path.abspath(os.path.join(self._hook_dir, dll_name))
        
        if not os.path.exists(dll_path):
            print(f"[LunaHook] DLL missing: {dll_path}")
            return False

        print(f"[LunaHook] Native Injecting {arch}-bit DLL...")
        kernel32 = windll.kernel32
        target_32 = (arch == "32")

        for pid in pids:
            h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
            if not h_process: continue
            
            try:
                path_bytes = dll_path.encode('utf-16-le') + b'\0\0'
                arg_len = len(path_bytes)
                remote_mem = kernel32.VirtualAllocEx(h_process, None, arg_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
                
                written = c_size_t(0)
                kernel32.WriteProcessMemory(h_process, remote_mem, path_bytes, arg_len, byref(written))

                h_kernel32 = get_remote_module_handle(int(pid), "kernel32.dll", target_32)
                
                if not h_kernel32:
                    print("[LunaHook] FAILED: Could not find 32-bit kernel32.dll in target.")
                    continue
                
                print(f"[LunaHook] Found correct kernel32 base at 0x{h_kernel32:x}")

                load_lib_addr = get_remote_proc_address(h_process, h_kernel32, "LoadLibraryW")
                
                if target_32 and load_lib_addr > 0xFFFFFFFF:
                    print(f"[LunaHook] ERROR: Still got a 64-bit address 0x{load_lib_addr:x}! Logic check failed.")
                    continue

                print(f"[LunaHook] Found LoadLibraryW at 0x{load_lib_addr:x}")

                thread_id = c_uint32(0)
                h_thread = kernel32.CreateRemoteThread(h_process, None, 0, c_void_p(load_lib_addr), c_void_p(remote_mem), 0, byref(thread_id))
                
                if h_thread:
                    print(f"[LunaHook] Injection success! Thread ID: {thread_id.value}")
                    kernel32.WaitForSingleObject(h_thread, 5000)
                    kernel32.VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE)
                    kernel32.CloseHandle(h_thread)
                    return True
                
            except Exception as e:
                print(f"[LunaHook] Injection Error: {e}")
            finally:
                kernel32.CloseHandle(h_process)
        
        return False

    def start(self, pid: int, output_callback) -> bool:
        self._output_handler = output_callback
        
        safe_output = OutputCallback(self._handle_output_safe)
        self._cb_refs = [safe_output] 

        procs = [
            ProcessEvent(lambda p: None), ProcessEvent(lambda p: None),
            ThreadEvent_maybeEmbed(lambda a,b,c,d: None), ThreadEvent(lambda a,b,c: None),
            safe_output, HostInfoHandler(lambda l,m: None),
            HookInsertHandler(lambda p,a,d: None), EmbedCallback(lambda n,t: None),
            I18NQueryCallback(lambda t: None),
        ]
        self._keeprefs = procs

        if not self.Luna_Start(*procs): return False
        if self.Luna_ResetLang: 
            try: self.Luna_ResetLang()
            except: pass

        self.Luna_ConnectProcess(pid)
        
        need_inject = False
        try: need_inject = self.Luna_CheckIfNeedInject(pid)
        except: pass

        if need_inject:
            is64 = _is_process_64bit(pid)
            arch = "64" if is64 else "32"
            print(f"[LunaHook] Target is {arch}-bit. Injecting...")
            if not self._injectdll([pid], arch):
                print("[LunaHook] Injection Step Failed.")
                return False

        try:
            self.Luna_InsertPCHooks(pid, 0)
            self.Luna_InsertPCHooks(pid, 1)
        except: pass

        print("[LunaHook] Hook Attached Successfully.")
        return True

    def stop(self):
        self._output_handler = None; self._keeprefs = []