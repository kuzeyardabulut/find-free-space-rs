//Importing necessary libraries
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcessModulesEx, GetModuleInformation};
use winapi::um::winnt::{
MEM_FREE,
HANDLE, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READWRITE,
MEMORY_BASIC_INFORMATION, PVOID, PROCESS_ALL_ACCESS};
use winapi::um::memoryapi::VirtualQueryEx;
use std::ptr;
use winapi::shared::minwindef::DWORD;
use winapi::um::tlhelp32::{PROCESSENTRY32, TH32CS_SNAPPROCESS, CreateToolhelp32Snapshot, Process32First, Process32Next};
use winapi::um::handleapi::CloseHandle;




//Function to find the free memory space
fn get_free_space(handle:HANDLE, base_addres: PVOID, last_addres: PVOID, data_len: usize) -> Result<PVOID, String> {
    // Provide the base address here
    let base_address: PVOID = base_addres as *mut _;

    // Create a memory information structure to find the last address
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    // Scan from the base address to the last address
    let mut current_address = base_address;
    while current_address as usize <= last_addres as usize - data_len {
        // Get the memory region's information
        let result = unsafe {
            VirtualQueryEx(
                handle,
                current_address,
                &mut mem_info as *mut _,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if result == 0 {
            panic!("VirtualQueryEx failed!");
        }

        // If the region is free and has a size of data_len bytes, then there is a free space.
        if mem_info.State == MEM_FREE && mem_info.RegionSize >= data_len {
            return Ok(current_address as PVOID);
        }
        // Move to the next memory region
        current_address  = ((current_address as usize) + mem_info.RegionSize as usize) as PVOID;
    }

    return Err(format!("No {} byte-sized space available.", data_len).to_string());
}

//Function to get the process handle
fn get_process_handle(pid: u32) -> Result<HANDLE, ()> {
    return Ok(unsafe {
        OpenProcess(
            PROCESS_ALL_ACCESS, 
            0, 
            pid
        )
    })
}

//Function to check the process
fn check_process(pid_num: u32, data_len: usize) -> Result<String, ()> {
        // Get the process ID from the user
        let pid = pid_num;

    // Create a handle for the process
    let handle: HANDLE = match get_process_handle(pid){
        Ok(e) => e,
        Err(_e) => return Err(())
    };
    if handle.is_null() {
        log::info!("Process handle creation error!");
    }
    else {
            // Find the process's modules and print their information
            let mut h_mods = [ptr::null_mut(); 1024];
            let mut needed = 0;
            if unsafe {
                EnumProcessModulesEx(
                    handle,
                    h_mods.as_mut_ptr(),
                    std::mem::size_of_val(&h_mods) as u32,
                    &mut needed,
                    0x03, // list all modules
                )
            } == 0
            {
            log::info!("Unable to Find Process Modules!");
            }
            else {
                let module_count = needed as usize / std::mem::size_of::<*mut u8>();
                log::info!("Process ID: {}\n", pid);
                log::info!("Number of modules found: {}\n", module_count);
                for i in 0..module_count {
                    let mut mod_info = winapi::um::psapi::MODULEINFO {
                        lpBaseOfDll: ptr::null_mut(),
                        SizeOfImage: 0,
                        EntryPoint: ptr::null_mut(),
                    };

                    if unsafe {
                        GetModuleInformation(
                            handle,
                            h_mods[i],
                            &mut mod_info as *mut _,
                            std::mem::size_of::<winapi::um::psapi::MODULEINFO>() as u32,
                        )
                    } == 0
                    {
                        log::info!("Unable to get module information!");
                    }
                    else {
                        
                    

                        let mut module_name = [0u8; 256];
                        if unsafe { winapi::um::psapi::GetModuleBaseNameA(handle, h_mods[i], module_name.as_mut_ptr() as _, 256) } == 0 {
                            log::info!("Unable to get module name!");
                        }
                        else {
                            
                    
                            let mut module_name_with_nul = module_name.to_vec();
                            module_name_with_nul.push(0);

                            log::info!(
                                "Module name: {:?}\nModule start address: {:p}\nModule end address: {:p}\nModule size: {}",
                                String::from_utf8_lossy(&module_name_with_nul).replace("\0", ""),
                                mod_info.lpBaseOfDll,
                                (mod_info.lpBaseOfDll as usize + mod_info.SizeOfImage as usize) as *mut u32,
                                mod_info.SizeOfImage,
                            );
                                // Modülün yetkilerini kontrol et ve yazdır
                                let page_info: winapi::shared::minwindef::DWORD;
                                let mut perm_string = String::new();
                                
                                let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                                let mem_info_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
                                let mem_info_ptr = &mut mem_info as *mut MEMORY_BASIC_INFORMATION;
                                
                                if unsafe { winapi::um::memoryapi::VirtualQueryEx(handle, mod_info.lpBaseOfDll, mem_info_ptr, mem_info_size) } == 0 {
                                    log::info!("Unable to get module page informations!");
                                }
                                else {
                                    
                                
                                page_info = unsafe { std::mem::transmute(mem_info.Protect) };


                                match page_info as u32 {
                                    PAGE_READONLY => perm_string.push_str("Read Only\n"),
                                    PAGE_READWRITE => perm_string.push_str("Read-Write\n"),
                                    PAGE_EXECUTE_READWRITE => perm_string.push_str("Read-Write-Execute\n"),
                                    _ => perm_string.push_str(format!("Unknown Page Permissions. Protection Code: {}\n", page_info).as_str()),
                                }
                                
                                match get_free_space(handle, mod_info.lpBaseOfDll, (mod_info.lpBaseOfDll as usize + mod_info.SizeOfImage as usize) as PVOID, data_len){
                                    Ok(e) => {println!("Find Empty Space: {:?}", e.clone()); println!("----------------------------------------\n"); return Ok(format!("{:?}", e).to_string());},
                                    Err(e) => {log::info!("Can't Find Empty Space: {}", e);log::info!("----------------------------------------\n")},
                                };
                                
                            }
                        }
                    }
                }
            }

            // Handle'ı kapat   
            unsafe {
                CloseHandle(handle);
            }
    }

    return Err(());
}

fn get_pid_list(data_len: usize){
    let mut processes: Vec<DWORD> = Vec::new();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == ptr::null_mut() {
        panic!("Cannot get process snapshot");
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as DWORD;

    let mut success = unsafe { Process32First(snapshot, &mut entry) };
    while success != 0 {
        let pid = entry.th32ProcessID;
        processes.push(pid);
        success = unsafe { Process32Next(snapshot, &mut entry) };
    }

    println!("[*] Scan Starting\n[*] Trying to Find Empty Space For Your Shellcode");
    for pid in processes {
        match check_process(pid, data_len){
            Ok(_e) => {log::info!("Successfully completed: {}", pid); return;},
            Err(_e) => log::info!("Unsuccessfully completed: {}", pid)
        };
    }
    println!("[*] Empty Space Not Found!")
}

fn main()-> Result<(), String>{

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        println!(r"Usage: .\find_empty_space.exe <empty spaces lenght>");
        println!(r"Example: .\find_empty_space.exe 100");
        std::process::exit(1);
    }

    let data_len: usize = match (&args[1]).parse(){
        Ok(e) => e,
        Err(_e) => return Err("Invalid argument. You can't translate this input to integer.".to_string())
    };
    get_pid_list(data_len);

    Ok(())
}
