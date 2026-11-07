//! run0 starts pkttyagent with --fallback, so a desktop's own agent takes
//! every prompt. An agent registered for this pid outranks it, and exec
//! keeps the pid and parent, so polkit's kept authorizations still match.

use std::ffi::{CStr, OsStr, OsString};
use std::fmt::Display;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicI32, Ordering::SeqCst};

mod dbus;

use dbus::{Bus, Call, Msg, Writer};

const AGENT_PATH: &str = "/run0tty/Agent";
const AGENT_INTERFACE: &str = "org.freedesktop.PolicyKit1.AuthenticationAgent";
const POLKIT: &str = "org.freedesktop.PolicyKit1";
const HELPER_SOCKET: &str = "/run/polkit/agent-helper.socket";

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_default();
    // run0's own pkttyagent finds this first in PATH and quietly exits.
    if Path::new(&argv0).file_name() == Some(OsStr::new("pkttyagent")) {
        return ExitCode::SUCCESS;
    }

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return fail("/proc/self/exe", e),
    };
    let Some(run0) = find_run0(&exe) else {
        eprintln!("run0-tty: no other run0 in PATH");
        return ExitCode::from(127);
    };

    let mut cmd = Command::new(&run0);
    cmd.arg0("run0").args(args);
    if unsafe { libc::geteuid() } != 0
        && let Ok(tty) = File::options()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/tty")
        && spawn_agent(tty)
    {
        cmd.env("PATH", quiet_path(&exe));
    }
    let e = cmd.exec();
    fail(run0.display(), e)
}

fn fail(what: impl Display, e: io::Error) -> ExitCode {
    eprintln!("run0-tty: {what}: {e}");
    ExitCode::from(126)
}

fn find_run0(exe: &Path) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("run0"))
        .find(|p| fs::canonicalize(p).is_ok_and(|real| real != exe))
}

fn quiet_path(exe: &Path) -> OsString {
    let mut path = exe.with_file_name("../libexec/run0-tty").into_os_string();
    if let Some(rest) = std::env::var_os("PATH").filter(|p| !p.is_empty()) {
        path.push(":");
        path.push(rest);
    }
    path
}

fn spawn_agent(tty: File) -> bool {
    let parent = unsafe { libc::getpid() };
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return false;
    }
    let (rx, tx) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };

    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            drop(rx);
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
            if unsafe { libc::getppid() } == parent {
                detach_stdio();
                if let Err(e) = agent(parent, tty, tx) {
                    eprintln!("run0-tty: agent: {e}");
                }
            }
            unsafe { libc::_exit(0) }
        }
        _ => {
            drop(tx);
            drop(tty);
            matches!((&rx).read(&mut [0]), Ok(1))
        }
    }
}

fn detach_stdio() {
    if let Ok(null) = File::options().read(true).write(true).open("/dev/null") {
        unsafe {
            libc::dup2(null.as_raw_fd(), 0);
            libc::dup2(null.as_raw_fd(), 1);
        }
    }
}

fn agent(parent: libc::pid_t, tty: File, mut ready: File) -> io::Result<()> {
    guard_signals();
    let mut bus = Bus::system()?;

    let mut name = Writer::default();
    name.str(POLKIT);
    let owner = bus.call(
        Call {
            dest: "org.freedesktop.DBus",
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
            member: "GetNameOwner",
        },
        "s",
        &name.0,
    )?;
    let polkit = owner.body().str().unwrap_or_default().to_owned();

    let mut subject = Writer::default();
    subject.str("unix-process");
    subject.array(8, |w| {
        w.pad(8);
        w.str("pid");
        w.sig("u");
        w.u32(parent as u32);
        w.pad(8);
        w.str("start-time");
        w.sig("t");
        // polkit reads zero as "look it up".
        w.u64(0);
    });
    subject.str("C");
    subject.str(AGENT_PATH);
    bus.call(
        Call {
            dest: POLKIT,
            path: "/org/freedesktop/PolicyKit1/Authority",
            interface: "org.freedesktop.PolicyKit1.Authority",
            member: "RegisterAuthenticationAgent",
        },
        "(sa{sv})ss",
        &subject.0,
    )?;
    ready.write_all(b"1")?;
    drop(ready);

    loop {
        let msg = bus.recv()?;
        if msg.kind != dbus::METHOD_CALL {
            continue;
        }
        let outcome = match (msg.interface.as_str(), msg.member.as_str()) {
            _ if msg.sender != polkit => Err((
                "org.freedesktop.DBus.Error.AccessDenied",
                "polkit only".into(),
            )),
            (AGENT_INTERFACE, "BeginAuthentication") => {
                begin(&tty, &msg).map_err(|e| ("org.freedesktop.PolicyKit1.Error.Failed", e))
            }
            (AGENT_INTERFACE, "CancelAuthentication") => Ok(()),
            _ => Err((
                "org.freedesktop.DBus.Error.UnknownMethod",
                "unknown method".into(),
            )),
        };
        bus.reply(&msg, outcome)?;
    }
}

fn begin(tty: &File, msg: &Msg) -> Result<(), String> {
    let (cookie, uids) = parse_begin(msg).ok_or("malformed BeginAuthentication")?;
    let user = pick_user(&uids).ok_or("no unix-user identity offered")?;
    match converse(tty, &user, &cookie) {
        Ok(true) => Ok(()),
        Ok(false) => Err("authentication failed".into()),
        Err(e) => Err(e.to_string()),
    }
}

fn parse_begin(msg: &Msg) -> Option<(String, Vec<u32>)> {
    if msg.signature != "sssa{ss}sa(sa{sv})" {
        return None;
    }
    let mut r = msg.body();
    for _ in 0..3 {
        r.str()?;
    }
    r.skip(b"a{ss}")?;
    let cookie = r.str()?.to_owned();
    let mut uids = Vec::new();
    r.array(8, |r| {
        let kind = r.str()?;
        r.array(8, |r| {
            let key = r.str()?;
            let sig = r.sig()?;
            if kind == "unix-user" && key == "uid" && sig == "u" {
                uids.push(r.u32()?);
                Some(())
            } else {
                r.skip(sig.as_bytes())
            }
        })
    })?;
    Some((cookie, uids))
}

fn pick_user(uids: &[u32]) -> Option<String> {
    let me = unsafe { libc::getuid() };
    let uid = uids
        .iter()
        .copied()
        .find(|&u| u == me)
        .or(uids.first().copied())?;
    user_name(uid)
}

fn user_name(uid: u32) -> Option<String> {
    let mut pw = MaybeUninit::<libc::passwd>::uninit();
    let mut buf = [0 as libc::c_char; 4096];
    let mut out = std::ptr::null_mut();
    let r =
        unsafe { libc::getpwuid_r(uid, pw.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr((*out).pw_name) };
    name.to_str().ok().map(str::to_owned)
}

fn converse(mut tty: &File, user: &str, cookie: &str) -> io::Result<bool> {
    let helper = UnixStream::connect(HELPER_SOCKET)?;
    (&helper).write_all(format!("{user}\n{cookie}\n").as_bytes())?;
    for line in BufReader::new(&helper).lines() {
        let line = line?;
        let (kind, msg) = line.split_once(' ').unwrap_or((&line, ""));
        match kind {
            "PAM_PROMPT_ECHO_OFF" | "PAM_PROMPT_ECHO_ON" => {
                let mut prompt = unescape(msg.as_bytes());
                if prompt == b"Password: " {
                    prompt = b"password: ".to_vec();
                }
                ask(tty, &helper, &prompt, kind == "PAM_PROMPT_ECHO_ON")?;
            }
            "PAM_TEXT_INFO" | "PAM_ERROR_MSG" => {
                let mut text = unescape(msg.as_bytes());
                text.push(b'\n');
                tty.write_all(&text)?;
            }
            "SUCCESS" => return Ok(true),
            "FAILURE" => return Ok(false),
            _ => {}
        }
    }
    Ok(false)
}

fn ask(mut tty: &File, mut helper: &UnixStream, prompt: &[u8], echo: bool) -> io::Result<()> {
    tty.write_all(prompt)?;
    let _quiet = if echo {
        None
    } else {
        Some(Quiet::new(tty.as_raw_fd())?)
    };
    // The tty is canonical, so one read is the whole line.
    let mut line = [0u8; 4097];
    let mut n = tty.read(&mut line[..4096])?;
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if line[n - 1] != b'\n' {
        line[n] = b'\n';
        n += 1;
    }
    let sent = helper.write_all(&line[..n]);
    wipe(&mut line);
    sent
}

fn wipe(bytes: &mut [u8]) {
    for b in bytes {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

struct Quiet;

impl Quiet {
    fn new(fd: RawFd) -> io::Result<Self> {
        unsafe {
            if libc::tcgetattr(fd, &raw mut SAVED) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut quiet = SAVED;
            quiet.c_lflag &= !libc::ECHO;
            quiet.c_lflag |= libc::ECHONL;
            TTY.store(fd, SeqCst);
            if libc::tcsetattr(fd, libc::TCSANOW, &quiet) != 0 {
                TTY.store(-1, SeqCst);
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Quiet)
    }
}

impl Drop for Quiet {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(TTY.load(SeqCst), libc::TCSANOW, &raw const SAVED) };
        TTY.store(-1, SeqCst);
    }
}

// The prompting tty, or -1, on which restore's calls fail harmlessly.
static TTY: AtomicI32 = AtomicI32::new(-1);
static mut SAVED: libc::termios = unsafe { std::mem::zeroed() };

extern "C" fn restore(sig: libc::c_int) {
    let fd = TTY.load(SeqCst);
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, &raw const SAVED);
        libc::write(fd, b"\n".as_ptr().cast(), 1);
        libc::_exit(128 + sig)
    }
}

fn guard_signals() {
    for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
        unsafe { libc::signal(sig, restore as *const () as libc::sighandler_t) };
    }
}

fn unescape(mut s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    while let [b, rest @ ..] = s {
        s = rest;
        if *b != b'\\' {
            out.push(*b);
            continue;
        }
        let octal = s
            .iter()
            .take(3)
            .take_while(|d| (b'0'..=b'7').contains(d))
            .count();
        if octal > 0 {
            let byte = s[..octal]
                .iter()
                .fold(0u8, |acc, d| acc.wrapping_mul(8).wrapping_add(d - b'0'));
            out.push(byte);
            s = &s[octal..];
            continue;
        }
        let [c, rest @ ..] = s else { break };
        s = rest;
        out.push(match c {
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'b' => 0x08,
            b'f' => 0x0c,
            b'v' => 0x0b,
            other => *other,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::unescape;

    #[test]
    fn unescapes_like_g_strescape() {
        assert_eq!(unescape(b"Password: "), b"Password: ");
        assert_eq!(unescape(br#"a\nb\\c\"d"#), b"a\nb\\c\"d");
        assert_eq!(unescape(br"\303\251"), "é".as_bytes());
    }
}
