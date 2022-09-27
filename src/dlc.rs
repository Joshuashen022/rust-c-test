pub const PCRE2_UCP: u32 = 131072;

pub const PCRE2_UTF: u32 = 524288;
pub type PCRE2_UCHAR8 = u8;
pub type PCRE2_SPTR8 = *const PCRE2_UCHAR8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_general_context_8 {
    _unused: [u8; 0],
}
pub type pcre2_general_context_8 = pcre2_real_general_context_8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_compile_context_8 {
    _unused: [u8; 0],
}
pub type pcre2_compile_context_8 = pcre2_real_compile_context_8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_match_context_8 {
    _unused: [u8; 0],
}
pub type pcre2_match_context_8 = pcre2_real_match_context_8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_convert_context_8 {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_code_8 {
    _unused: [u8; 0],
}
pub type pcre2_code_8 = pcre2_real_code_8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_match_data_8 {
    _unused: [u8; 0],
}
pub type pcre2_match_data_8 = pcre2_real_match_data_8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_jit_stack_8 {
    _unused: [u8; 0],
}
extern "C" {
    pub fn pcre2_compile_8(
        arg1: PCRE2_SPTR8,
        arg2: usize,
        arg3: u32,
        arg4: *mut ::libc::c_int,
        arg5: *mut usize,
        arg6: *mut pcre2_compile_context_8,
    ) -> *mut pcre2_code_8;
}
extern "C" {
    pub fn pcre2_code_free_8(arg1: *mut pcre2_code_8);
}
extern "C" {
    pub fn pcre2_match_data_create_from_pattern_8(
        arg1: *const pcre2_code_8,
        arg2: *mut pcre2_general_context_8,
    ) -> *mut pcre2_match_data_8;
}

extern "C" {
    pub fn pcre2_match_8(
        arg1: *const pcre2_code_8,
        arg2: PCRE2_SPTR8,
        arg3: usize,
        arg4: usize,
        arg5: u32,
        arg6: *mut pcre2_match_data_8,
        arg7: *mut pcre2_match_context_8,
    ) -> ::libc::c_int;
}
extern "C" {
    pub fn pcre2_match_data_free_8(arg1: *mut pcre2_match_data_8);
}

extern "C" {
    pub fn pcre2_get_ovector_pointer_8(arg1: *mut pcre2_match_data_8) -> *mut usize;
}
