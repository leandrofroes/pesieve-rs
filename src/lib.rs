use std::env;
use std::path::Path;
use lazy_static::lazy_static;
use libloading::{Library, Symbol};
use std::os::raw::{c_ulong, c_char};

const PESIEVE_MIN_VER: u32 = 0x040000; // minimal version of the PE-sieve DLL to work with this wrapper
const PESIEVE_MAX_VER: u32 = 0x040100; // maximal version of the PE-sieve DLL to work with this wrapper

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum OutputFilter {
	OUT_FULL = 0,
	OUT_NO_DUMPS = 1,
	OUT_NO_DIR = 2,
	OUT_FILTERS_COUNT = 3,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum ShellcMode {
	SHELLC_NONE = 0,
	SHELLC_PATTERNS = 1,
	SHELLC_STATS = 2,
	SHELLC_PATTERNS_OR_STATS = 3,
	SHELLC_PATTERNS_AND_STATS = 4,
	SHELLC_COUNT = 5,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum ObfuscMode {
	OBFUSC_NONE = 0,
	OBFUSC_STRONG_ENC = 1,
	OBFUSC_WEAK_ENC = 2,
	OBFUSC_ANY = 3,
	OBFUSC_COUNT = 4,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum ImpRecMode {
	PE_IMPREC_NONE = 0,
	PE_IMPREC_AUTO = 1,
	PE_IMPREC_UNERASE = 2,
	PE_IMPREC_REBUILD0 = 3,
	PE_IMPREC_REBUILD1 = 4,
	PE_IMPREC_REBUILD2 = 5,
	PE_IMPREC_MODES_COUNT = 6,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum DumpMode {
	PE_DUMP_AUTO = 0,
	PE_DUMP_VIRTUAL = 1,
	PE_DUMP_UNMAP = 2,
	PE_DUMP_REALIGN = 3,
	PE_DUMP_MODES_COUNT = 4,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum IatScanMode {
	PE_IATS_NONE = 0,
	PE_IATS_CLEAN_SYS_FILTERED = 1,
	PE_IATS_ALL_SYS_FILTERED = 2,
	PE_IATS_UNFILTERED = 3,
	PE_IATS_MODES_COUNT = 4,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum DotnetPolicy {
	PE_DNET_NONE = 0,
	PE_DNET_SKIP_MAPPING = 1,
	PE_DNET_SKIP_SHC = 2,
	PE_DNET_SKIP_HOOKS = 3,
	PE_DNET_SKIP_ALL = 4,
	PE_DNET_COUNT = 5,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum DataScanMode {
	PE_DATA_NO_SCAN = 0,
	PE_DATA_SCAN_DOTNET = 1,
	PE_DATA_SCAN_NO_DEP = 2,
	PE_DATA_SCAN_ALWAYS = 3,
	PE_DATA_SCAN_INACCESSIBLE = 4,
	PE_DATA_SCAN_INACCESSIBLE_ONLY = 5,
	PE_DATA_COUNT = 6,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum JsonLevel {
	JSON_BASIC = 0,
	JSON_DETAILS = 1,
	JSON_DETAILS2 = 2,
	JSON_LVL_COUNT = 3,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum ResultsFilter{
	SHOW_NONE = 0,
	SHOW_ERRORS = 1,
	SHOW_NOT_SUSPICIOUS = 2,
	SHOW_SUSPICIOUS = 3,
	SHOW_SUSPICIOUS_AND_ERRORS = 4,
	SHOW_SUCCESSFUL_ONLY = 5,
	SHOW_ALL = 6,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum ReportType {
	REPORT_NONE = 0,
	REPORT_SCANNED = 1,
	REPORT_DUMPED = 2,
	REPORT_ALL = 3,
}

#[repr(C)]
pub struct ParamString {
	pub length: c_ulong,
	pub buffer: *const c_char,
}

#[repr(C)]
pub struct Params {
	pub pid: c_ulong,
	pub dotnet_policy: DotnetPolicy,
	pub imprec_mode: ImpRecMode,
	pub quiet: bool,
	pub out_filter: OutputFilter,
	pub no_hooks: bool,
	pub shellcode: ShellcMode,
	pub obfuscated: ObfuscMode,
	pub threads: bool,
	pub iat: IatScanMode,
	pub data: DataScanMode,
	pub minidump: bool,
	pub rebase: bool,
	pub dump_mode: DumpMode,
	pub json_output: bool,
	pub make_reflection: bool,
	pub use_cache: bool,
	pub json_lvl: JsonLevel,
	pub results_filter: ResultsFilter,
	pub output_dir: *const c_char,
	pub modules_ignored: ParamString,
	pub pattern_file: ParamString,
}

#[repr(C)]
pub struct Report {
	pub pid: c_ulong,
	pub is_managed: bool,
	pub is_64bit: bool,
	pub is_reflection: bool,
	pub scanned: c_ulong,
	pub suspicious: c_ulong,
	pub replaced: c_ulong,
	pub hdr_mod: c_ulong,
	pub unreachable_file: c_ulong,
	pub patched: c_ulong,
	pub iat_hooked: c_ulong,
	pub implanted: c_ulong,
	pub implanted_pe: c_ulong,
	pub implanted_shc: c_ulong,
	pub other: c_ulong,
	pub skipped: c_ulong,
	pub errors: c_ulong,
}

type PesiveHelpT = unsafe extern "C" fn();
type PESieveScanT = unsafe extern "C" fn(params: Params) -> Report;
type PESieveScanExT = unsafe extern "C" fn(
	params: Params, 
	rtype: ReportType, 
	json_buf: *mut c_char , 
	json_buf_size: usize, 
	buf_needed_size: *mut usize
) -> Report;

lazy_static! {
	static ref lib: Library = {
		let dll_path = env::var("PESIEVE_DIR").unwrap_or(".".to_string());

		let dll_name = if cfg!(target_arch = "x86_64") {
			"pe-sieve64.dll"
		} else if cfg!(target_arch = "x86") {
			"pe-sieve32.dll"
		} else {
			panic!("[!] Arch not supported!");
		};

		let full_path = Path::new(&dll_path).join(dll_name);

		if !full_path.exists() {
			panic!("[!] PESieve DLL not found.");
		}

		unsafe { 
			Library::new(full_path).expect("[!] Failed to load pe-sieve DLL.") 
		}
	};

	static ref PESieve_version: Symbol<'static, &'static c_ulong> =  unsafe { 
		lib.get(b"PESieve_version").expect("[!] Failed to load PESieve_version symbol") 
	};

	static ref PESieve_help: Symbol<'static, PesiveHelpT> = unsafe { 
		lib.get(b"PESieve_help").expect("[!] Failed to load PESieve_help symbol") 
	};

	static ref PESieve_scan: Symbol<'static, PESieveScanT> =  unsafe { 
		lib.get(b"PESieve_scan").expect("[!] Failed to load PESieve_scan symbol") 
	};

	static ref PESieve_scan_ex: Symbol<'static, PESieveScanExT> =  unsafe { 
		lib.get(b"PESieve_scan_ex").expect("[!] Failed to load PESieve_scan_ex symbol") 
	};
}

fn version_to_str(version_val: u32) -> String {
	assert!(version_val != 0);

	let major = (version_val >> 24) & 0xFF;
	let minor = (version_val >> 16) & 0xFF;
	let patch = (version_val >> 8) & 0xFF;
	let build = version_val & 0xFF;

	format!("{major}.{minor}.{patch}.{build}")
}

fn check_version() {
	let version = ***PESieve_version;

	if version < PESIEVE_MIN_VER || version > PESIEVE_MAX_VER {
		let dll_version_str = version_to_str(version);
		panic!("[!] The PE-sieve.dll version {} doesn't match the bindings version", dll_version_str);
	}
}

pub fn pesieve_help() {
	check_version();

	unsafe { PESieve_help() }
}

pub fn pesieve_scan(params: Params) -> Report {
	check_version();

	unsafe { PESieve_scan(params) }
}

pub fn pesieve_scan_ex(params: Params, rtype: ReportType, json_buf_size: usize) -> (Report, String, usize) {
	check_version();

	let mut json_buf = vec![0u8; json_buf_size];
	let mut buf_needed_size: usize = 0;

	let report: Report = unsafe {
		PESieve_scan_ex(
			params, 
			rtype, 
			json_buf.as_mut_ptr().cast::<c_char>(), 
			json_buf.len(), 
			&mut buf_needed_size
		)
	};

	if buf_needed_size > json_buf.len() {
		print!("[!] The provided buffer size is not enough. Need {} bytes.\n", buf_needed_size);
	}

	let result_json: String = String::from_utf8(json_buf).unwrap();

	(report, result_json, buf_needed_size)
}
