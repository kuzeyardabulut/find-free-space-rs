# Windows Process Memory Scanner
The code provided is a Rust program that interacts with the Windows API to inspect the memory of a process and find a free memory space of a specific size within it. The program first defines several functions, including get_free_space, which finds a free space in memory of a specific size, and get_process_handle, which obtains a handle to a process based on its ID. The check_process function is then defined, which takes the process ID and the desired data length as arguments and uses the other functions to inspect the process's memory and find the free space.

To find a free memory space of a specific size, the program scans the process's memory region by region, starting at the provided base address and continuing until the last address minus the data length. If a memory region is free and has a size greater than or equal to the desired data length, the program returns the starting address of the region. If no free space of the required size is found, the function returns an error message.

## Installation
This program requires Rust to be installed. If you don't have Rust installed, you can download it from the official website.

After installing Rust, clone this repository and navigate to the root directory of the project. Then, run the `cargo build --release` command to build the program.

This will build the program in release mode and generate an executable file in the target/release/ directory.

## Usage
To use the program, run the executable file with the following command-line arguments:
 `Usage: .\find_empty_space.exe <empty space lenght> `
 `Example: .\find_empty_space.exe 1000`
Here, [data length] is the length of the data you want to find a space for in memory.

The program will scan the memory of the process and print information about the modules loaded in the process. If a free space of the specified size is found, the program will print its address in memory.

## License
This program is licensed under the [MIT License](https://github.com/kuzeyardabulut/find-free-space-rs/blob/main/LICENSE).





