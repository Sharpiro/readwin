use anyhow::Result;
use extension::{OptionTExt, ResultTEExt};
use std::ffi::CStr;
use zerocopy::{FromBytes, Immutable, KnownLayout};

pub mod extension;

fn main() -> Result<()> {
    let filename = std::env::args().nth(1).ok("filename")?;
    let binary_buffer = std::fs::read(filename)?;

    let dos_header =
        ImageDosHeader::ref_from_bytes(&binary_buffer[..size_of::<ImageDosHeader>()]).anyhow()?;
    let image_header_start = usize::try_from(dos_header.e_lfanew)?;
    let winpe_header = WinPEHeader::ref_from_bytes(
        &binary_buffer[image_header_start..image_header_start + size_of::<WinPEHeader>()],
    )
    .anyhow()?;
    let section_headers_start = image_header_start + size_of::<WinPEHeader>();
    let section_headers_len = winpe_header.image_file_header.number_of_sections.into();
    let section_headers = <[SectionHeader]>::ref_from_bytes_with_elems(
        &binary_buffer[section_headers_start..][..size_of::<SectionHeader>() * section_headers_len],
        section_headers_len,
    )
    .anyhow()?;
    let entrypoint = winpe_header.image_optional_header.image_base
        + u64::from(winpe_header.image_optional_header.address_of_entry_point);
    let pe_magic = winpe_header.image_optional_header.magic;
    let dos_magic = std::str::from_utf8(&u16::to_le_bytes(dos_header.e_magic))?.to_string();

    println!("PE Header:");
    println!("DOS Magic: {:#x?}", dos_magic);
    println!("PE Magic: {pe_magic:#x?}");
    println!(
        "Class: {}",
        if pe_magic == 0x10b { "PE32" } else { "PE32+" }
    );
    println!(
        "Image base: {:#x?}",
        winpe_header.image_optional_header.image_base
    );
    println!(
        "Base of code: {:#x?}",
        winpe_header.image_optional_header.base_of_code
    );
    println!("Entry point address: {entrypoint:#x?}");
    println!("Section headers start: {section_headers_start:#x?}");
    println!("Section headers length: {section_headers_len}");
    println!("Section header size: {}", size_of::<SectionHeader>());

    println!();
    println!("Section Headers:");
    for (i, section_header) in section_headers.iter().enumerate() {
        let name = CStr::from_bytes_until_nul(&section_header.name)?.to_str()?;
        let address = winpe_header.image_optional_header.image_base
            + u64::from(section_header.virtual_address);
        println!(
            "{i}, {name:?}, {size:#04x}, {address:#04x}, {file_offset:#04x}, {characteristics:#10x}",
            size = section_header.virtual_size,
            file_offset = section_header.pointer_to_raw_data,
            characteristics = section_header.characteristics,
        );
    }

    Ok(())
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct ImageDosHeader {
    pub e_magic: u16,      // Magic number ("MZ")
    pub e_cblp: u16,       // Bytes on last page of file
    pub e_cp: u16,         // Pages in file
    pub e_crlc: u16,       // Relocations
    pub e_cparhdr: u16,    // Size of header in paragraphs
    pub e_minalloc: u16,   // Minimum extra paragraphs needed
    pub e_maxalloc: u16,   // Maximum extra paragraphs needed
    pub e_ss: u16,         // Initial (relative) SS value
    pub e_sp: u16,         // Initial SP value
    pub e_csum: u16,       // Checksum
    pub e_ip: u16,         // Initial IP value
    pub e_cs: u16,         // Initial (relative) CS value
    pub e_lfarlc: u16,     // File address of relocation table
    pub e_ovno: u16,       // Overlay number
    pub e_res: [u16; 4],   // Reserved words
    pub e_oemid: u16,      // OEM identifier
    pub e_oeminfo: u16,    // OEM information
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: i32,     // File address of new exe header
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct ImageFileHeader {
    pub machine: u16,                 // Target machine type
    pub number_of_sections: u16,      // Number of sections
    pub time_date_stamp: u32,         // Timestamp
    pub pointer_to_symbol_table: u32, // Pointer to symbol table (deprecated)
    pub number_of_symbols: u32,       // Number of symbols (deprecated)
    pub size_of_optional_header: u16, // Size of the optional header
    pub characteristics: u16,         // Flags indicating file characteristics
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct ImageDataDirectory {
    pub virtual_address: u32, // Relative virtual address (RVA) of the directory
    pub size: u32,            // Size of the directory in bytes
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct ImageOptionalHeader {
    pub magic: u16,               // Identifies PE32 or PE32+
    pub major_linker_version: u8, // Linker version
    pub minor_linker_version: u8,
    pub size_of_code: u32,                   // Size of .text section
    pub size_of_initialized_data: u32,       // Size of initialized data
    pub size_of_uninitialized_data: u32,     // Size of uninitialized data
    pub address_of_entry_point: u32,         // RVA of entry point
    pub base_of_code: u32,                   // RVA of code section
    pub image_base: u64,                     // Preferred load address
    pub section_alignment: u32,              // Alignment of sections in memory
    pub file_alignment: u32,                 // Alignment of sections in file
    pub major_operating_system_version: u16, // Minimum OS version
    pub minor_operating_system_version: u16,
    pub major_image_version: u16, // Image version
    pub minor_image_version: u16,
    pub major_subsystem_version: u16, // Subsystem version
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,     // Reserved, should be 0
    pub size_of_image: u32,           // Total image size
    pub size_of_headers: u32,         // Combined size of headers
    pub checksum: u32,                // Checksum of the image
    pub subsystem: u16,               // Subsystem (e.g., GUI, Console)
    pub dll_characteristics: u16,     // DLL characteristics flags
    pub size_of_stack_reserve: u64,   // Stack reserve size
    pub size_of_stack_commit: u64,    // Stack commit size
    pub size_of_heap_reserve: u64,    // Heap reserve size
    pub size_of_heap_commit: u64,     // Heap commit size
    pub loader_flags: u32,            // Loader flags
    pub number_of_rva_and_sizes: u32, // Number of data directory entries
    pub data_directory: [ImageDataDirectory; 16], // Array of data directories
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct WinPEHeader {
    pub signature: u32,
    pub image_file_header: ImageFileHeader,
    pub image_optional_header: ImageOptionalHeader,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct SectionHeader {
    pub name: [u8; 8],               // Section name (8 bytes)
    pub virtual_size: u32,           // Total size of the section when loaded into memory
    pub virtual_address: u32,        // Address of the section relative to the image base
    pub size_of_raw_data: u32,       // Size of the section in the file
    pub pointer_to_raw_data: u32,    // File pointer to the section's data
    pub pointer_to_relocations: u32, // File pointer to relocations (deprecated in modern PE)
    pub pointer_to_linenumbers: u32, // File pointer to line numbers (deprecated)
    pub number_of_relocations: u16,  // Number of relocation entries
    pub number_of_linenumbers: u16,  // Number of line number entries
    pub characteristics: u32,        // Flags describing section attributes
}
