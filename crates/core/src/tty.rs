//! The terminal: reading a secret without echo, and measuring the screen.
#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::AsRawFd;

/// Read a line from the controlling terminal with echo off. Fails when there is no terminal,
/// which is the case under an agent's shell tool: the secret has to come from a person.
pub fn prompt_secret(prompt: &str) -> io::Result<String> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    write!(tty, "{prompt}")?;
    tty.flush()?;
    let fd = tty.as_raw_fd();

    // SAFETY: termios calls on a file descriptor we just opened and own; the struct is fully
    // initialised by tcgetattr before use, and the original settings are restored below.
    let original = unsafe {
        let mut t = std::mem::zeroed::<libc::termios>();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err(io::Error::last_os_error());
        }
        t
    };
    let mut quiet = original;
    quiet.c_lflag &= !libc::ECHO;
    // SAFETY: as above.
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, &quiet);
    }
    let mut line = String::new();
    let read = BufReader::new(&tty).read_line(&mut line);
    // SAFETY: restoring the settings we read.
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, &original);
    }
    let _ = writeln!(tty);
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Is there a person at a terminal?
pub fn has_tty() -> bool {
    OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok()
}

/// Columns on the terminal attached to stdout, else `$COLUMNS`, else 80. Never below 40.
pub fn width() -> usize {
    // SAFETY: TIOCGWINSZ writes a winsize struct we own into the buffer we pass.
    let from_tty = unsafe {
        let mut size = std::mem::zeroed::<libc::winsize>();
        (libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) == 0 && size.ws_col > 0).then_some(size.ws_col as usize)
    };
    let from_env = std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok());
    from_tty.or(from_env).unwrap_or(80).clamp(40, 200)
}
