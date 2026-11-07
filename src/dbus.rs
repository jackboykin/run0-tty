use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";
const MAX_MESSAGE: usize = 1 << 27;
pub const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;

pub struct Bus {
    sock: UnixStream,
    serial: u32,
}

#[derive(Default)]
pub struct Msg {
    pub kind: u8,
    serial: u32,
    reply_serial: u32,
    pub sender: String,
    pub interface: String,
    pub member: String,
    pub signature: String,
    body: Vec<u8>,
}

impl Msg {
    pub fn body(&self) -> Reader<'_> {
        Reader {
            buf: &self.body,
            pos: 0,
        }
    }
}

pub struct Call<'a> {
    pub dest: &'a str,
    pub path: &'a str,
    pub interface: &'a str,
    pub member: &'a str,
}

impl Bus {
    pub fn system() -> io::Result<Self> {
        let mut sock = UnixStream::connect(SYSTEM_BUS)?;
        let uid = unsafe { libc::getuid() }.to_string();
        let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        sock.write_all(format!("\0AUTH EXTERNAL {hex}\r\nBEGIN\r\n").as_bytes())?;
        let mut line = Vec::new();
        let mut byte = [0];
        while !line.ends_with(b"\r\n") {
            sock.read_exact(&mut byte)?;
            line.push(byte[0]);
        }
        if !line.starts_with(b"OK ") {
            return Err(io::Error::other("system bus refused authentication"));
        }
        let mut bus = Self { sock, serial: 0 };
        bus.call(
            Call {
                dest: "org.freedesktop.DBus",
                path: "/org/freedesktop/DBus",
                interface: "org.freedesktop.DBus",
                member: "Hello",
            },
            "",
            &[],
        )?;
        Ok(bus)
    }

    pub fn call(&mut self, call: Call, signature: &str, body: &[u8]) -> io::Result<Msg> {
        let fields = [
            Field::Path(call.path),
            Field::Interface(call.interface),
            Field::Member(call.member),
            Field::Destination(call.dest),
        ];
        let serial = self.send(METHOD_CALL, &fields, signature, body)?;
        loop {
            let msg = self.recv()?;
            if msg.reply_serial != serial {
                continue;
            }
            match msg.kind {
                METHOD_RETURN => return Ok(msg),
                ERROR => {
                    let text = msg.body().str().unwrap_or_default().to_owned();
                    return Err(io::Error::other(format!("{}: {text}", call.member)));
                }
                _ => {}
            }
        }
    }

    pub fn reply(&mut self, to: &Msg, outcome: Result<(), (&str, String)>) -> io::Result<()> {
        let mut fields = vec![
            Field::ReplySerial(to.serial),
            Field::Destination(&to.sender),
        ];
        match outcome {
            Ok(()) => self.send(METHOD_RETURN, &fields, "", &[]),
            Err((name, text)) => {
                let mut body = Writer::default();
                body.str(&text);
                fields.push(Field::ErrorName(name));
                self.send(ERROR, &fields, "s", &body.0)
            }
        }
        .map(drop)
    }

    fn send(
        &mut self,
        kind: u8,
        fields: &[Field],
        signature: &str,
        body: &[u8],
    ) -> io::Result<u32> {
        self.serial += 1;
        let mut w = Writer::default();
        w.0.extend([b'l', kind, 0, 1]);
        w.u32(body.len() as u32);
        w.u32(self.serial);
        let signature = (!body.is_empty()).then_some(Field::Signature(signature));
        w.array(8, |w| {
            for &field in fields.iter().chain(&signature) {
                match field {
                    Field::Path(s) => {
                        w.field(1, "o");
                        w.str(s);
                    }
                    Field::Interface(s) => {
                        w.field(2, "s");
                        w.str(s);
                    }
                    Field::Member(s) => {
                        w.field(3, "s");
                        w.str(s);
                    }
                    Field::ErrorName(s) => {
                        w.field(4, "s");
                        w.str(s);
                    }
                    Field::ReplySerial(n) => {
                        w.field(5, "u");
                        w.u32(n);
                    }
                    Field::Destination(s) => {
                        w.field(6, "s");
                        w.str(s);
                    }
                    Field::Signature(s) => {
                        w.field(8, "g");
                        w.sig(s);
                    }
                }
            }
        });
        w.pad(8);
        w.0.extend(body);
        self.sock.write_all(&w.0)?;
        Ok(self.serial)
    }

    pub fn recv(&mut self) -> io::Result<Msg> {
        let mut head = [0; 16];
        self.sock.read_exact(&mut head)?;
        if head[0] != b'l' {
            return Err(io::Error::other("big-endian D-Bus message"));
        }
        let word = |at: usize| {
            u32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]) as usize
        };
        let body_at = (16 + word(12)).next_multiple_of(8);
        let len = body_at + word(4);
        if len > MAX_MESSAGE {
            return Err(io::Error::other("oversized D-Bus message"));
        }
        let mut buf = vec![0; len];
        buf[..16].copy_from_slice(&head);
        self.sock.read_exact(&mut buf[16..])?;

        let mut msg = Msg {
            kind: head[1],
            serial: word(8) as u32,
            ..Msg::default()
        };
        let mut r = Reader { buf: &buf, pos: 12 };
        r.array(8, |r| {
            let code = *r.take(1)?.first()?;
            let sig = r.sig()?;
            match (code, sig) {
                (2, "s") => msg.interface = r.str()?.to_owned(),
                (3, "s") => msg.member = r.str()?.to_owned(),
                (5, "u") => msg.reply_serial = r.u32()?,
                (7, "s") => msg.sender = r.str()?.to_owned(),
                (8, "g") => msg.signature = r.sig()?.to_owned(),
                _ => r.skip(sig.as_bytes())?,
            }
            Some(())
        })
        .ok_or_else(|| io::Error::other("malformed D-Bus header"))?;
        msg.body = buf.split_off(body_at);
        Ok(msg)
    }
}

#[derive(Clone, Copy)]
enum Field<'a> {
    Path(&'a str),
    Interface(&'a str),
    Member(&'a str),
    ErrorName(&'a str),
    ReplySerial(u32),
    Destination(&'a str),
    Signature(&'a str),
}

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn pad(&mut self, n: usize) {
        self.0.resize(self.0.len().next_multiple_of(n), 0);
    }

    pub fn u32(&mut self, n: u32) {
        self.pad(4);
        self.0.extend(n.to_le_bytes());
    }

    pub fn u64(&mut self, n: u64) {
        self.pad(8);
        self.0.extend(n.to_le_bytes());
    }

    pub fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend(s.as_bytes());
        self.0.push(0);
    }

    pub fn sig(&mut self, s: &str) {
        self.0.push(s.len() as u8);
        self.0.extend(s.as_bytes());
        self.0.push(0);
    }

    fn field(&mut self, code: u8, sig: &str) {
        self.pad(8);
        self.0.push(code);
        self.sig(sig);
    }

    pub fn array(&mut self, align: usize, f: impl FnOnce(&mut Self)) {
        self.u32(0);
        let at = self.0.len() - 4;
        self.pad(align);
        let start = self.0.len();
        f(self);
        let len = (self.0.len() - start) as u32;
        self.0[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn align(&mut self, n: usize) {
        self.pos = self.pos.next_multiple_of(n);
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let bytes = self.buf.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(bytes)
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.align(4);
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    pub fn str(&mut self) -> Option<&'a str> {
        let n = self.u32()? as usize;
        let s = self.take(n)?;
        self.take(1)?;
        std::str::from_utf8(s).ok()
    }

    pub fn sig(&mut self) -> Option<&'a str> {
        let n = *self.take(1)?.first()? as usize;
        let s = self.take(n)?;
        self.take(1)?;
        std::str::from_utf8(s).ok()
    }

    pub fn array(
        &mut self,
        align: usize,
        mut f: impl FnMut(&mut Self) -> Option<()>,
    ) -> Option<()> {
        let len = self.u32()? as usize;
        self.align(align);
        let end = self.pos.checked_add(len)?;
        while self.pos < end {
            self.align(align);
            f(self)?;
        }
        (self.pos == end).then_some(())
    }

    pub fn skip(&mut self, sig: &[u8]) -> Option<()> {
        match *sig.first()? {
            b'y' => drop(self.take(1)?),
            b'n' | b'q' => {
                self.align(2);
                self.take(2)?;
            }
            b'b' | b'i' | b'u' | b'h' => drop(self.u32()?),
            b'x' | b't' | b'd' => {
                self.align(8);
                self.take(8)?;
            }
            b's' | b'o' => drop(self.str()?),
            b'g' => drop(self.sig()?),
            b'v' => {
                let inner = self.sig()?;
                self.skip(inner.as_bytes())?;
            }
            b'a' => {
                let len = self.u32()? as usize;
                self.align(alignment(*sig.get(1)?));
                self.take(len)?;
            }
            b'(' | b'{' => {
                self.align(8);
                let mut inner = sig.get(1..sig.len() - 1)?;
                while !inner.is_empty() {
                    let n = type_len(inner);
                    self.skip(&inner[..n])?;
                    inner = &inner[n..];
                }
            }
            _ => return None,
        }
        Some(())
    }
}

fn alignment(code: u8) -> usize {
    match code {
        b'y' | b'g' | b'v' => 1,
        b'n' | b'q' => 2,
        b'x' | b't' | b'd' | b'(' | b'{' => 8,
        _ => 4,
    }
}

fn type_len(sig: &[u8]) -> usize {
    let mut depth = 0;
    for (i, &c) in sig.iter().enumerate() {
        match c {
            b'(' | b'{' => depth += 1,
            b')' | b'}' => depth -= 1,
            b'a' => continue,
            _ => {}
        }
        if depth == 0 {
            return i + 1;
        }
    }
    sig.len()
}

#[cfg(test)]
mod tests {
    use super::{Reader, Writer, type_len};

    #[test]
    fn finds_complete_types() {
        assert_eq!(type_len(b"a(sa{sv})s"), 9);
        assert_eq!(type_len(b"{ss}"), 4);
        assert_eq!(type_len(b"us"), 1);
    }

    #[test]
    fn round_trips_a_dict() {
        let mut w = Writer::default();
        w.str("x");
        w.array(8, |w| {
            w.pad(8);
            w.str("uid");
            w.sig("u");
            w.u32(1000);
        });
        w.str("after");
        let mut r = Reader { buf: &w.0, pos: 0 };
        assert_eq!(r.str(), Some("x"));
        r.skip(b"a{sv}").unwrap();
        assert_eq!(r.str(), Some("after"));
    }
}
