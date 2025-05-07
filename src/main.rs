use phf::phf_set;
use regex::Regex;
use std::path::Path;



pub static R_FIRST_PATH_SET: phf::Set<&'static str> = phf_set! {
    "execve", "stat", "lstat", "access", "statfs",
    "readlink", "getxattr", "lgetxattr", "llistxattr",
};

pub static W_FIRST_PATH_SET: phf::Set<&'static str> = phf_set! {
    "mkdir", "rmdir", "truncate", "creat", "chmod", "chown",
    "lchown", "utime", "mknod", "utimes", "acct", "unlink",
    "setxattr", "removexattr",
};

pub static R_FD_PATH_SET: phf::Set<&'static str> = phf_set! {
    "fstatat", "newfstatat", "statx", "name_to_handle_at",
    "readlinkat", "faccessat", "execveat", "faccessat2",
};

pub static W_FD_PATH_SET: phf::Set<&'static str> = phf_set! {
    "unlinkat", "utimensat", "mkdirat", "mknodat", "fchownat", "futimeat",
    "linkat", "fchmodat",
};

pub static IGNORE_SET: phf::Set<&'static str> = phf_set! {
    "getpid", "getcwd",
};

const RE:  &str =  "((?:\"[^\"\n]*\"|<[^>\n]*>|{[^}\n]*}|[^,\n])+)";

fn split_args(s: &str) -> Vec<String>{
    let re = Regex::new(RE).unwrap();
    re.captures_iter(s)
        .map(|cap| cap[1].to_string())
        .collect()
}

fn take_first_args(s: &str) -> (&str, &str) {
    let re = Regex::new(RE).unwrap();
    let mat = re.find(s).unwrap();
    let first = mat.as_str();
    let rest_idx = mat.end() +1;
    let rest = if rest_idx <= s.len() {
        &s[rest_idx..]
    } else {
        ""
    };

    (first, rest)
}

#[derive(Debug, Clone, PartialEq)]
struct ExitStatus {
    exitcode: i32,
}

fn parse_info(l: &str) -> ExitStatus {
    if l.contains("exited") {
        let start = "+++ exited with ".len();
        let end = l.len() - " +++".len();
        let exitcode_str = &l[start..end];
        let exitcode = exitcode_str.trim().parse::<i32>().expect("Error parsing exit code");
        ExitStatus { exitcode }
    } else if l.contains("Killed") {
        ExitStatus { exitcode: -1 }
    } else {
        panic!("Unhandled input: {l}");
    }
}

fn main() {


    println!("Hello, world!");
}
