//! A pkttyagent that asks with one quiet line. systemd tools start the
//! first pkttyagent in PATH to answer their polkit queries on the terminal.
//! They pass --fallback, which would hand every prompt to a desktop's agent;
//! this one takes them all.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering::SeqCst};

mod dbus;

use dbus::{Bus, Call, Msg, Writer};

const AGENT_PATH: &str = "/run0tty/Agent";
const AGENT_INTERFACE: &str = "org.freedesktop.PolicyKit1.AuthenticationAgent";
const POLKIT: &str = "org.freedesktop.PolicyKit1";
const HELPER_SOCKET: &str = "/run/polkit/agent-helper.socket";
const USAGE: &str = "usage: pkttyagent [--fallback] [--notify-fd FD] [--process PID]";

struct Options {
    notify: Option<File>,
    process: libc::pid_t,
}

fn main() -> ExitCode {
    let Some(opts) = options() else {
        eprintln!("{USAGE}");
        return ExitCode::from(126);
    };
    let tty = File::options()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/tty");
    match tty.and_then(|tty| agent(opts, tty)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pkttyagent: {e}");
            ExitCode::from(127)
        }
    }
}

fn options() -> Option<Options> {
    let mut opts = Options {
        notify: None,
        process: unsafe { libc::getppid() },
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        let mut value = || inline.clone().or_else(|| args.next());
        match name {
            "--fallback" => {}
            "--notify-fd" => {
                let fd: RawFd = value()?.parse().ok().filter(|&fd| fd > 2)?;
                opts.notify = Some(unsafe { File::from_raw_fd(fd) });
            }
            "--process" | "-p" => opts.process = value()?.split(',').next()?.parse().ok()?,
            _ => return None,
        }
    }
    (opts.process > 1).then_some(opts)
}

fn agent(opts: Options, tty: File) -> io::Result<()> {
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
        w.u32(opts.process as u32);
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
    drop(opts.notify);

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

struct Request {
    message: String,
    cookie: String,
    uids: Vec<u32>,
}

fn begin(mut tty: &File, msg: &Msg) -> Result<(), String> {
    let req = parse_begin(msg).ok_or("malformed BeginAuthentication")?;
    let user = pick_user(&req.uids).ok_or("no unix-user identity offered")?;
    if let Some(reason) = reason(&req.message) {
        let line = match std::env::var_os("NO_COLOR") {
            Some(v) if !v.is_empty() => format!("{reason}\n"),
            _ => format!("\x1b[2m{reason}\x1b[0m\n"),
        };
        tty.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    }
    match converse(tty, &user, &req.cookie) {
        Ok(true) => Ok(()),
        Ok(false) => Err("authentication failed".into()),
        Err(e) => Err(e.to_string()),
    }
}

// A transient unit's name is generated, and whoever started it knows why.
fn reason(message: &str) -> Option<&str> {
    let reason = message
        .strip_prefix("Authentication is required to ")
        .unwrap_or(message);
    let reason = reason.strip_suffix('.').unwrap_or(reason);
    (!reason.is_empty() && !reason.starts_with("start transient unit ")).then_some(reason)
}

fn parse_begin(msg: &Msg) -> Option<Request> {
    if msg.signature != "sssa{ss}sa(sa{sv})" {
        return None;
    }
    let mut r = msg.body();
    r.str()?;
    let message = r.str()?.to_owned();
    r.str()?;
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
    Some(Request {
        message,
        cookie,
        uids,
    })
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
    use super::{reason, unescape};

    #[test]
    fn reasons_skip_transient_units() {
        let m = "Authentication is required to restart 'nginx.service'.";
        assert_eq!(reason(m), Some("restart 'nginx.service'"));
        let m = "Authentication is required to start transient unit 'run-p1-i2.service'.";
        assert_eq!(reason(m), None);
        assert_eq!(reason("Something else"), Some("Something else"));
    }

    #[test]
    fn unescapes_like_g_strescape() {
        assert_eq!(unescape(b"Password: "), b"Password: ");
        assert_eq!(unescape(br#"a\nb\\c\"d"#), b"a\nb\\c\"d");
        assert_eq!(unescape(br"\303\251"), "é".as_bytes());
    }
}
