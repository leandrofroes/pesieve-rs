 use std::ffi::CString;

fn main() {
    let out_dir = CString::new("").unwrap();
    let out_dir_ptr = out_dir.as_ptr(); 

    let modules_ignored = CString::new("").unwrap();
    let modules_ignored_ptr = modules_ignored.as_ptr(); 

    let pattern_file = CString::new("").unwrap();
    let pattern_file_ptr = pattern_file.as_ptr(); 

    let params = pesieve_rs::Params{
        pid: 12345,
        dotnet_policy: pesieve_rs::DotnetPolicy::PE_DNET_SKIP_MAPPING,
        imprec_mode: pesieve_rs::ImpRecMode::PE_IMPREC_AUTO,
        quiet: false,
        out_filter: pesieve_rs::OutputFilter::OUT_FULL,
        no_hooks: false,
        shellcode: pesieve_rs::ShellcMode::SHELLC_NONE,
        obfuscated: pesieve_rs::ObfuscMode::OBFUSC_NONE,
        threads: true,
        iat: pesieve_rs::IatScanMode::PE_IATS_CLEAN_SYS_FILTERED,
        data: pesieve_rs::DataScanMode::PE_DATA_SCAN_NO_DEP,
        minidump: false,
        rebase: false,
        dump_mode: pesieve_rs::DumpMode::PE_DUMP_AUTO, 
        json_output: true,
        make_reflection: false,
        use_cache: false,
        json_lvl: pesieve_rs::JsonLevel::JSON_BASIC,
        results_filter: pesieve_rs::ResultsFilter::SHOW_SUSPICIOUS,
        output_dir: out_dir_ptr,
        modules_ignored: pesieve_rs::ParamString {length: 0, buffer: modules_ignored_ptr},
        pattern_file: pesieve_rs::ParamString {length: 0, buffer: pattern_file_ptr},
    };

    let json_max_size: usize = 1024;
    let rtype: pesieve_rs::ReportType = pesieve_rs::ReportType::REPORT_ALL;

    let results: (pesieve_rs::Report, String, usize) = pesieve_rs::pesieve_scan_ex(params, rtype, json_max_size);

    let(report, json, out_size) = results;

    print!("PID: {:}\n", report.pid);
    print!("Out size: {:}\n", out_size);
    print!("JSON: {:}\n", json);
}