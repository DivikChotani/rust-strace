use phf::phf_set;
use regex::{bytes, Regex};
use std::fs::FileTimes;
use std::io::Bytes;
use std::path::Path;
use std::collections::{HashMap, HashSet};
use std::{fs, os};
use std::path::PathBuf;
use unescape;
use std::env;
use std::fs::File;
use std::io::{self, BufRead};


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
#[derive(Debug, Clone, PartialEq)]
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
// fn get_path_first_path(pid: i32, args: &str, ctx: &mut Context) -> PathBuf{
//     let a = parse_string(&split_args(args)[1]);

//     convert_absolute(Path::new(& ctx.get_dir(pid)), &a)
// }

fn get_path_first_path(pid: i32, args: &str, ctx: &mut Context) -> Result<PathBuf, &'static str> {
    let a = parse_string(&split_args(args)[0]); 

    let dir = ctx.get_dir(pid);
    let abs_path = convert_absolute(Path::new(&dir), &a);

    if abs_path.as_os_str().is_empty() {
        Err("path resolution failed")
    } else {
        Ok(abs_path)
    }
}


fn parse_r_first_path(pid: i32, args: &str, ret: &str, ctx: &mut Context) -> rwFile {
    rwFile::rfile(RFile::new(&get_path_first_path(pid, args, ctx)
        .unwrap()
        .to_str()
        .expect("failed to create rfile, parse_r_first_path")))
}

fn parse_w_first_path(pid: i32, args: &str, ret: &str, ctx: &mut Context) -> rwFile {
    if is_ret_err(ret) {
        rwFile::rfile(RFile::new(&get_path_first_path(pid, args, ctx)
            .unwrap()
            .to_str()
            .expect("failed to create rfile, parse_r_first_path")))
    }
    else {
        rwFile::wfile(WFile::new(&get_path_first_path(pid, args, ctx)
            .unwrap()
            .to_str()
            .expect("failed to create rfile, parse_r_first_path")))
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
    let new_path = get_path_first_path(pid, args, ctx).expect("failed parse chdir in get path first path");
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

fn parse_openat(args:  &str, ret :&str) -> Option< Vec<rwFile>>{
    let args = split_args(args);
    let path = parse_string(&args[1]);
    let dfd = &args[1];
    let p = Path::new(&path);
    let flags = &args[2];
    if path.len() == 0{
        return None
    };
    let total_path = if is_absolute_path(&path) {
        Path::new(&path.clone()).to_path_buf()
    } else {
        let begin = dfd.find("<").unwrap() +1;
        let end = (&dfd[begin..]).find(">").unwrap() + begin;
        let pwd = &dfd[begin..end];
        Path::new(pwd).join(&path)
    };
    Some(handle_open_common(total_path, flags, ret))
}

fn parse_open(pid:i32, args:  &str, ret :&str, ctx: &mut Context) -> Option<Vec<rwFile>>{
    let total_path = match get_path_first_path(pid, args, ctx) {
        Ok(path) => path,
        Err(_) => return None
    };

    let flags = &split_args(&args)[1];

    Some(handle_open_common(total_path, flags, ret))

}

fn get_path_from_fd_path(args:  &str) -> PathBuf{
    let t = &split_args(args);

    let a0 = &t[0];
    let a1 = &t[1];

    let a1 = parse_string(a1);
    if a1.len() != 0 && a1.starts_with('/') {
        Path::new(&a1).to_path_buf()
    } else {
        let begin = a0.find("<").unwrap() +1;
        let end = (&a0[begin..]).find(">").unwrap() + begin;
        let a0 = &a0[begin..end];
        Path::new(&a1).join(&a0)
    }

}

fn parse_renameat(pid:i32, args:  &str, ret :&str, ctx: &mut Context) -> Vec<rwFile> {
    let path_a = get_path_from_fd_path(args);
    let second_set = &(split_args(args)[2..].join(","));
    let path_b = get_path_from_fd_path(second_set);
    vec![rwFile::wfile(WFile::new(&path_a.to_str().expect("could not turn path A to str in parse rename at"))), 
        rwFile::wfile(WFile::new(&path_b.to_str().expect("could not turn path B to str in parse rename at")))]
}

fn parse_r_fd_path(args:  &str, ret :&str) -> rwFile {
    rwFile::rfile(RFile::new(& get_path_from_fd_path(args).to_str().expect("failed in parse r fd path")))
}

fn parse_w_fd_path(args:  &str, ret :&str) -> rwFile {
    if is_ret_err(ret) {
        rwFile::rfile(RFile::new(& get_path_from_fd_path(args).to_str().expect("failed in parse r fd path")))
    } else {
        rwFile::wfile(WFile::new(& get_path_from_fd_path(args).to_str().expect("failed in parse r fd path")))
    }
}

fn has_clone_fs(flags: &str) -> bool {
    if flags.contains("CLONE_FS"){
        true
    } else{
        false
    }
}

fn parse_clone(pid:i32, args:  &str, ret :&str, ctx: &mut Context) {
    let child = match ret.trim().parse() {
        Ok(num) => num,
        Err(_) => -1
    };
    if child < 0 {
        return
    }
    let arg_list: Vec<String> = split_args(args)
        .into_iter()
        .map(|x:String| x.trim().to_string())
        .collect();

    let flags: String = arg_list
        .into_iter()
        .find(|x| x.starts_with("flags="))
        .map(|x| x["flags=".len()..].to_string()).expect("failed in finding flags in arg list");

    if has_clone_fs(&flags) {
        ctx.do_clone(pid, child);
    }
}


fn parse_symlinkat(pid:i32, args:  &str, ret :&str) -> rwFile {
    let t = take_first_args(args);
    parse_w_fd_path(t.0, t.1)
}

fn parse_symlink(pid:i32, args:  &str, ret :&str, ctx: &mut Context) -> rwFile {
    let t = take_first_args(args);
    parse_w_first_path(pid, t.1, ret, ctx)
}

fn parse_inotify_add_watch(pid:i32, args:  &str, ret :&str, ctx: &mut Context) -> rwFile {
    let (_, rest) = take_first_args(args);
    parse_r_first_path(pid, rest, ret, ctx)
}

fn parse_syscall(pid: i32, syscall: &str, args:  &str, ret :&str, ctx: &mut Context)-> Result<Vec<rwFile>,&'static str>{
    let t: Result<Vec<rwFile>,&str> = match syscall {
        s if R_FIRST_PATH_SET.contains(s) => Ok(vec![parse_r_first_path(pid, args, ret, ctx)]),
        s if W_FIRST_PATH_SET.contains(s) => Ok(vec![parse_w_first_path(pid, args, ret, ctx)]),
        "openat" => Ok(parse_openat(args, ret).expect("failed openat syscall in parse_syscall")),
        "chdir" => Ok(vec![parse_chdir(pid, args, ret, ctx)]),
        "open" => Ok(parse_open(pid, args, ret, ctx).expect("failed open syscall in parse_syscall")),
        s if R_FD_PATH_SET.contains(s) => Ok(vec![parse_r_fd_path(args, ret)]),
        s if W_FD_PATH_SET.contains(s) => Ok(vec![parse_w_fd_path(args, ret)]),
        "rename" => Ok(parse_rename(pid, args, ret, ctx)),
        "renameat" | "renameat2" => Ok(parse_renameat(pid, args, ret, ctx)),
        "symlinkat" => Ok(vec![parse_symlinkat(pid, args, ret)]),
        "symlink" | "link" => Ok(vec![parse_symlink(pid, args, ret, ctx)]),
        "clone" => Err("Parse clone returns nothing"),
        "inotify_add_watch" => Ok(vec![parse_inotify_add_watch(pid, args, ret, ctx)]),
        s if IGNORE_SET.contains(s) => return Err("syscall in ignore set"),
        _ => Err("Unclassified syscall: {syscall}"),
    };
    t
}

fn strip_pid(l: &str) -> (i32, String){
    if l.chars().next().unwrap().is_ascii_digit(){
        let pair: Vec<& str> = l.split(" ").collect();
        return (pair[0].parse().unwrap(), pair[1..].concat())

    }
    panic!("expected pid at strip pid")
}

fn handle_info(l: &str) -> (bool, Option<ExitStatus>) {
    if l.ends_with("+++") {
        (true, Some(parse_info(l)))
    }
    else if l.ends_with("---") {
        (true, None)
    }
    else {
        (false, None)
    }

}
enum parse_line_ret {
    None,
    info(Option<ExitStatus>),
    files(Vec<rwFile>),
}
fn parse_line(l: &str, ctx: &mut Context) -> parse_line_ret {
    if l.len() == 0 {
        return parse_line_ret::None
    };
    let (pid, l) = strip_pid(l);
    if l.len() == 0 {
        return parse_line_ret::None
    }
    let (is_info, info) = handle_info(&l);
    if is_info {
        return parse_line_ret::info(info)
    };

    if l.contains("<unfinished") {
        ctx.push_half_line(pid, &l);
        return parse_line_ret::None
    }
    let l =  if l.contains("resumed>") {
        ctx.pop_complete_line(pid, &l)
    } else {
        "".to_string()
    };

    let (lparen, equals) = match (l.find('('), l.rfind('=')) {
         (Some(l), Some(e)) => (l, e),
    _ => {
        return parse_line_ret::None;
        }
    };

    let Some(rparen) = (&l[lparen..]).rfind(')') else {
        return parse_line_ret::None;
    };

    let syscall = &l[..rparen];
    let ret = &l[equals+1..];
    let args = &l[lparen+1..rparen];

    return parse_line_ret::files(parse_syscall(pid, syscall, args, ret, ctx)
                .expect("failed parse_syscall fn call from parse_line"))

}

fn parse_exit_code(trace_object: &Vec<String>) -> Option<i32>{
    if trace_object.len() == 0 || trace_object[0].is_empty() {
        return None
    };

    let l = &trace_object[0];
    let (first_pid, _) = strip_pid(l);
    for l in trace_object {
        let (pid, tmpl) = strip_pid(l);
        let (is_info, info) = handle_info(l);
        if is_info && pid == first_pid && info.is_some() {
            let temp = info.unwrap();
            return Some(temp.exitcode);
        }
    };
    panic!("No exitcode in parse_exit_code");
}

fn parse_and_gather_cmd_rw_sets(trace_object: &Vec<String>, ctx: &mut Context) -> (HashSet<String>, HashSet<String>) {
    let mut read_set: HashSet<String> = HashSet::new();
    let mut write_set: HashSet<String> = HashSet::new();

    let mut records: Vec<rwFile> = Vec::new();

    for l in trace_object {
        if let parse_line_ret::files(files) = parse_line(l, ctx) {
            for f in files {
                let keep = match &f {
                    rwFile::rfile(r) => !r.fname.starts_with("/tmp/pash_spec") && !r.fname.starts_with("/dev"),
                    rwFile::wfile(w) => !w.fname.starts_with("/tmp/pash_spec") && !w.fname.starts_with("/dev"),
                };
                if keep {
                    records.push(f);
                }
            }
        }
    }

    let mut all_records: Vec<rwFile> = Vec::new();

    for record in records {
        match record {
            rwFile::rfile(rf) => {
                for r in rf.closure() {
                    all_records.push(rwFile::rfile(r));
                }
            },
            rwFile::wfile(wf) => {
                for r in wf.closure() {
                    all_records.push(rwFile::wfile(r));
                }
            },
        }
    }

    for record in all_records {
        match record {
            rwFile::rfile(rf) => {
                if rf.fname != "/dev/tty" {
                    read_set.insert(rf.fname);
                }
            },
            rwFile::wfile(wf) => {
                if wf.fname != "/dev/tty" {
                    write_set.insert(wf.fname);
                }
            },
        }
    };

    return (read_set, write_set)
}
fn process_file(fname: &str, ctx: &mut Context) -> std::io::Result<()> {
    let file = File::open(fname)?;
    let reader = io::BufReader::new(file);

    for (i, line_result) in reader.lines().enumerate() {
        let line = line_result?; // handle possible I/O error
        if let parse_line_ret::files(record) = parse_line(&line, ctx){
            println!("{:?}", record); 
        }
    }

    Ok(())
}
fn main() {
    let mut ctx = Context::new();
    ctx.set_dir(env::current_dir().unwrap().to_str().unwrap(), None);
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    };
    let fname = &args[1];
    if let Err(e) = process_file(fname, &mut ctx) {
        eprintln!("Error: {}", e);
    }
}
