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
#[derive(Debug, Clone, PartialEq)]
struct RFile {
     
    fname: String,

} 
impl RFile {
    fn new(path: &str) -> Self {
        RFile {
            fname: path.to_string(),
        }
    }

    fn closure(&self) -> Vec<RFile> {

        let mut all_files = vec![self.clone()];

        if !self.fname.starts_with('/') {
            return all_files;
        }

        let mut current_path = Path::new(&self.fname);
        let mut depth = 0;

        while let Some(parent) = current_path.parent() {
            if parent == Path::new("") || parent == Path::new("/") {
                break;
            }

            all_files.push(RFile {
                fname: parent.display().to_string(),
            });

            current_path = parent;
            depth += 1;
            if depth > 512 {
                panic!("Path closure exceeded 512 levels");
            }
        }

        all_files
    }
}

#[derive(Debug, Clone, PartialEq)]
struct WFile {
     
    fname: String,

} 
impl WFile {
    fn new(path: &str) -> Self {
        WFile {
            fname: path.to_string(),
        }
    }

    fn closure(&self) -> Vec<WFile> {

        let mut all_files = vec![self.clone()];

        if !self.fname.starts_with('/') {
            return all_files;
        }

        let mut current_path = Path::new(&self.fname);
        let mut depth = 0;

        while let Some(parent) = current_path.parent() {
            if parent == Path::new("") || parent == Path::new("/") {
                break;
            }

            all_files.push(WFile {
                fname: parent.display().to_string(),
            });

            current_path = parent;
            depth += 1;
            if depth > 512 {
                panic!("Path closure exceeded 512 levels");
            }
        }

        all_files
    }
}
fn main() {


    println!("Hello, world!");
}
