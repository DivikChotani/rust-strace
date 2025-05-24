use phf::phf_set;
use regex::{bytes, Regex};
use std::io::Bytes;
use std::path::Path;
use std::collections::HashMap;
use std::{fs, os};
use std::path::PathBuf;
use unescape;


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
        // let path_buf = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
        //might need to revert to this later
        WFile {
            // fname: path_buf.to_str().unwrap().to_string(),
            fname: path.to_string()
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

enum rwFile {
    rfile(RFile),
    wfile(WFile)
}
struct Context {
    line_dict: HashMap<i32, String>,
    curdir_dict: HashMap<i32, String>,
    pid_group_dict: HashMap<i32, i32>,
    curdir_fallback: String,
}

impl Context {
    fn new()->Context {
        let line_dict = HashMap::new();
        let curdir_dict = HashMap::new();
        let pid_group_dict = HashMap::new();
        let path = String::from("");
        Context { 
            line_dict: line_dict, 
            curdir_dict: curdir_dict, 
            pid_group_dict: pid_group_dict,
            curdir_fallback: path 
        }
    }

    fn do_clone(&mut self, parent: i32, child: i32){
        self.pid_group_dict.insert(child, parent);
    }

    fn set_dir(&mut self, path: & str, pid: Option<i32>){
        self.curdir_fallback = path.to_string().clone();
        let mut pid = pid.unwrap_or(-1);
        if pid != -1 && self.pid_group_dict.contains_key(&pid) {
            pid = self.pid_group_dict.get(&pid).copied().unwrap_or(-1);
        }
        if pid != -1 {
            self.curdir_dict.insert(pid, path.to_string().clone());
        }
    }

    fn get_dir(&mut self, pid: i32) -> String{
        let mut pid = pid;
        if self.pid_group_dict.contains_key(& pid) {
            pid = self.pid_group_dict.get(& pid).copied().unwrap_or(-1);
        }

        if !self.pid_group_dict.contains_key(& pid) {
            let temp = self.curdir_fallback.clone();
            self.curdir_dict.insert(pid, temp );
        }

        return self.curdir_dict.get(& pid).cloned().expect("Unexpected error")
    }

    fn push_half_line(& mut self, pid: i32, l: & str){
        let s = match l.find("<unfinished") {
            Some(pos) => &l[0..pos],
            None => ""
        };
        let s = s.trim().to_string();
        self.line_dict.insert(pid, s);
        
    }

    fn pop_complete_line(&mut self, pid: i32, l: &str) -> String {
        let index = match l.find("resumed>") {
            Some(pos) => pos + "resumed>".len(),
            None => return "ERROR".to_string()
        };
        let line = self.line_dict.get(&pid).expect("not found");
        let line = line.clone() + &l[index..];
        self.line_dict.remove(&pid);
        return line;



    }
}

fn parse_string(s: &str) -> String {
    let mut s = s.trim();

    if s.eq("NULL") {
       return String::new()
    }

    if s.ends_with("...") {
        let l = s.len()-"...".len();
        s = &s[..l];
    }
    if !s.starts_with('"') || !s.ends_with('"') {
        panic!("Unexpected behaviour");
    }

    s = &s[1..s.len()-1];

    unescape::unescape(s).unwrap_or_else(|| s.to_string())
}   

fn between(s: &str, d1: &str, d2: &str) -> Option<(usize, usize)> {
    let a = s.find(d1)?;
    let b = s.rfind(d2)?;
    Some((a+ d1.len(), b))
}

fn is_absolute_path(path: &str) -> bool{
    !path.is_empty() && path.starts_with('/')
}

fn is_ret_err(ret: &str) -> bool{
    ret.trim().starts_with('-')
}

fn get_ret_file_path(ret :&str) -> String{
    if !is_ret_err(ret) {
        panic!("Unexpected behaviour passed into function get_ret_file_path")
    };
    let ret = ret.trim();
    let start = ret.find("<").unwrap() +1;
    let end = ret.rfind(">").unwrap() +1;

    (&ret[start..end]).to_string()
}

fn convert_absolute(cur_dir: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if is_absolute_path(path){
        p.to_path_buf()
    } else {
        cur_dir.join(p)
    }

}

fn get_path_first_path(pid: i32, args: &str, ctx: &mut Context) -> PathBuf{
    let a = parse_string(&split_args(args)[1]);

    convert_absolute(Path::new(& ctx.get_dir(pid)), &a)
}

fn parse_r_first_path(pid: i32, args: &str, ret: &str, ctx: &mut Context) -> rwFile {
    rwFile::rfile(RFile::new(&get_path_first_path(pid, args, ctx).to_str().expect("failed to create rfile, parse_r_first_path")))
}

fn parse_w_first_path(pid: i32, args: &str, ret: &str, ctx: &mut Context) -> rwFile {
    if is_ret_err(ret) {
        rwFile::rfile(RFile::new(&get_path_first_path(pid, args, ctx).to_str().expect("failed to create rfile, parse_r_first_path")))
    }
    else {
        rwFile::wfile(WFile::new(&get_path_first_path(pid, args, ctx).to_str().expect("failed to create rfile, parse_r_first_path")))
    }
}

enum argPos {
    single(i32),
    multiple(Vec<i32>,)
}

//potential error in the python version? fixxed here
fn get_path_at(pid: i32, positions: argPos, args:  &str, ctx: &mut Context) -> Vec<PathBuf>{
    let args = split_args(args);

    match positions {
        argPos::single(i) =>{
            let m = &args[1];
            vec![convert_absolute(Path::new(& ctx.get_dir(pid)), &parse_string(m))]
        }
        argPos::multiple(l) => {
            let mut res: Vec<PathBuf> = Vec::new();
            for arg in &args {
                res.push(convert_absolute(Path::new(& ctx.get_dir(pid)), &parse_string(arg)));
            }
            res
        }
    }
}

fn parse_rename(pid: i32, args: &str, ret: &str, ctx: &mut Context) -> Vec<rwFile> {
    let paths = get_path_at(pid, argPos::multiple(vec![0,1]), args, ctx);
    vec![
        rwFile::wfile(WFile::new(&paths[0].to_str()
            .expect("failed to create rfile, parse_r_first_path"))),
        rwFile::wfile(WFile::new(&paths[1].to_str()
            .expect("failed to create rfile, parse_r_first_path"))),
        ]
}

fn parse_link(pid: i32, args: &str, ret: &str, ctx: &mut Context) -> Vec<rwFile> {
    let paths = get_path_at(pid, argPos::multiple(vec![0,1]), args, ctx);
    vec![
        rwFile::rfile(RFile::new(&paths[0].to_str()
            .expect("failed to create rfile, parse_r_first_path"))),
        rwFile::wfile(WFile::new(&paths[1].to_str()
            .expect("failed to create rfile, parse_r_first_path"))),
        ]

}

fn parse_chdir(pid: i32, args: &str, ret: &str, ctx: &mut Context) -> rwFile {
    let new_path = get_path_first_path(pid, args, ctx);
    if !is_ret_err(ret) {
        ctx.set_dir((new_path.to_str().expect("failed to set to path")), Some(pid));
    }

    rwFile::rfile(RFile::new(&new_path.to_str().expect("failed in creating file in parse chdir")))

}

fn handle_open_flag(flags: &str) -> char{
    if flags.contains("O_RDONLY") {
        return 'r'
    }
    'w'
}

fn handle_open_common(total_path: PathBuf, flags: &str, ret :&str) -> Vec<rwFile>{
    let file_path =total_path.to_str().expect("error in handle open common returning rfile");
    if is_ret_err(ret){
        vec![rwFile::rfile(RFile::new(file_path))]
    }
    else if handle_open_flag(flags) == 'r' {
        vec![rwFile::rfile(RFile::new(file_path)), rwFile::rfile(RFile::new(&get_ret_file_path(ret)))]
    }
    else {
        vec![rwFile::wfile(WFile::new(file_path)), rwFile::wfile(WFile::new(&get_ret_file_path(ret)))]

    }
}
fn main() {

    let T = WFile::new("./Cargo.toml");
    let q = T.closure();

    for item in q {
        let name = item.fname;
        println!("{name}")
    }
    println!("Hello, world!");
}
