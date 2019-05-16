// This is a legacy logging interface internal to XS4ALL.
//
// Data is logged to a file, which gets moved away every second or
// so by an external logshipping process.
//
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration,SystemTime,UNIX_EPOCH};

use fs2::FileExt;
use futures::{Future,sink,Sink,Stream};
use futures::sync::mpsc::{Sender,Receiver,channel};
use lazy_static::lazy_static;

// LogSender, send data to the logging thread.
struct LogSender {
    tx:         Sender<Datalog>,
    tx_wait:    sink::Wait<Sender<Datalog>>,
}

// Producer side of the log channel.
lazy_static! {
    static ref LOGGER: Mutex<Option<LogSender>> = Mutex::new(None);
}

/// Returned by datalog::init().
pub(crate) struct LogGuard {
    handle:     Option<thread::JoinHandle<()>>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        let tx = {
            let mut guard = LOGGER.lock().unwrap();
            let mut logger = guard.take().unwrap();
            let _ = logger.tx_wait.close();
            logger.tx
        };
        let _ = tx.wait().close();
        let _ = self.handle.take().unwrap().join();
    }
}

/// Log a `Datalog` item. Synchronous and thus blocking.
/// panics if datalog::init() has not yet been called.
pub(crate) fn log_sync(item: Datalog) {
    let mut guard = LOGGER.lock().unwrap();
    let logger = guard.as_mut().unwrap();
    let _ = logger.tx_wait.send(item);
}

/// Log a `Datalog` item. Asynchronous.
/// panics if datalog::init() has not yet been called.
#[allow(dead_code)]
pub(crate) fn log_async(item: Datalog) -> impl Future<Item=Sender<Datalog>, Error=io::Error> {
    let mut guard = LOGGER.lock().unwrap();
    let logger = guard.as_mut().unwrap();
    logger.tx.clone().send(item).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// Initialize the datalog logging system.
///
/// Returns a guard handle. When the handle is dropped, the logging thread
/// will process all remaining datalog items in the channel and then exit.
pub(crate) fn init(filename: impl ToString) -> io::Result<LogGuard> {
    let handle = LogWriter::init(filename)?;
    Ok(LogGuard{ handle: Some(handle) })
}

// LogWriter, receives log messages and writes them to disk.
struct LogWriter {
    file:   Option<fs::File>,
    name:   String,
    dev:    u64,
    ino:    u64,
    recv:   Option<Receiver<Datalog>>,
}

impl LogWriter {

    // Initialize logwriter. If the datalog file cannot be
    // opened, return an error. Otherwise spawn a background
    // thread to process log messages and return the thread handle.
    fn init(filename: impl ToString) -> io::Result<thread::JoinHandle<()>> {
        let (tx, rx) = channel(0);
        let mut guard = LOGGER.lock().unwrap();
        *guard = Some(LogSender{
            tx:         tx.clone(),
            tx_wait:    tx.wait(),
        });
        let mut d = LogWriter {
            file:   None,
            name:   filename.to_string(),
            dev:    0,
            ino:    0,
            recv:   Some(rx),
        };
        d.reopen(false)?;
        Ok(thread::spawn(move || {
            d.run();
        }))
    }

    // re-open the datalog file.
    fn reopen(&mut self, retry: bool) -> io::Result<()> {
        self.file.take();
        loop {
            let res = fs::OpenOptions::new()
                .append(true)
                .truncate(false)
                .create(true)
                .open(&self.name);
            match res {
                Ok(file) => {
                    let meta = file.metadata().unwrap();
                    self.dev = meta.dev();
                    self.ino = meta.ino();
                    self.file = Some(file);
                    break;
                },
                Err(e) => {
                    if !retry {
                        return Err(e);
                    }
                    thread::sleep(Duration::from_millis(1000));
                },
            }
        }
        Ok(())
    }

    // lock file, then check to see if it has changed. if it has,
    // reopen file, and keep trying until it is stable.
    fn check_and_lock(&mut self) -> bool {
        let mut did_reopen = false;
        loop {
            if let Some(ref mut file) = self.file {
                if file.lock_exclusive().is_ok() {
                    if let Ok(meta) = fs::metadata(&self.name) {
                        if meta.dev() == self.dev && meta.ino() == self.ino {
                            break;
                        }
                    }
                }
            }
            let _ = self.reopen(true);
            did_reopen = true;
        }
        did_reopen
    }

    // main logging loop.
    fn run(&mut self) {

        // Get a single-threaded tokio executor.
        let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();

        // timer.
        let tick =  tokio::timer::Interval::new_interval(Duration::from_millis(1000));
        let tick = tick.map(|_| Datalog::default()).map_err(|_| ());

        // combined stream of ticks and messages.
        let recv = self.recv.take().unwrap();
        let strm = recv.select(tick);

        // logging loop.
        let mut log_is_empty = false;
        let logger = strm.for_each(move |item| {

            // empty, so just a timer tick?
            if item.is_empty() {
                if !log_is_empty {
                    log_is_empty = self.check_and_lock();
                    let file = self.file.as_mut().unwrap();
                    if file.unlock().is_err() {
                        self.file.take();
                    }
                }
                return Ok(());
            }

            // write the datalog item.
            let (line1, line2) = item.to_lines();
            loop {
                self.check_and_lock();
                let file = self.file.as_mut().unwrap();
                if write!(file, "{}\n{}\n", line1, line2).is_ok() {
                    if file.unlock().is_err() {
                        self.file.take();
                    }
                    break;
                }
                self.file.take();
            }
            log_is_empty = false;
            Ok(())
        });

        let _ = runtime.block_on(logger);
    }
}

// A log entry.
#[derive(Debug, Clone)]
pub(crate) struct Datalog {
    // timestamp
    pub time:           SystemTime,
    // ip address where the request came from
    pub src_ip:         IpAddr,
    // "username" as sent in auth-request (radius attr 1)
    pub username:       String,
    // username got mapped to this underlying account (datalog 25:"XS4/401:<account>")
    pub account:        Option<String>,
    // "clientip" sent in auth-request (radius attr 31)
    pub clientip:       Option<IpAddr>,
    // "callingsystem" sent in auth-request (radius attr 32)
    pub callingsystem:  Option<String>,
    // Accept = Ok(()), Reject - Err(e).
    pub status:         Result<(), Error>,
    // error message overriding default error log_message (radius attr 24)
    pub message:        Option<String>,
}

impl Default for Datalog {
    fn default() -> Datalog {
        Datalog {
            time:           SystemTime::UNIX_EPOCH,
            src_ip:         [0u8, 0u8, 0u8, 0u8].into(),
            username:       "".to_string(),
            account:        None,
            clientip:       None,
            callingsystem:  None,
            status:         Ok(()),
            message:        None,
        }
    }
}

// 25:XS4/401:<data>
// "data" is extra escaped. Well, escaped ... troublesome chars replaced with a dot.
fn attr_xs401(attr: usize, msg: impl AsRef<str>) -> String {
    let msg = msg.as_ref().replace(|c| c == ':' || c == ';' || c == '"' || c == ',', ".");
    attr_string(attr, &format!("XS4/401:{}", msg))
}

// sanitize a string.
fn sanitize(s: impl AsRef<str>) -> String {
    const C_ESC: &'static str = "'\"`()[]\\,";
    let s = s.as_ref();
    let mut r = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        let cx = c as u32;
        if cx < 256 {
            if cx < 32 || cx > 126 || C_ESC.contains(c) {
                r.push_str(&format!("\\{:03o}", cx));
            } else {
                r.push(c);
            }
        } else {
            r.extend(c.escape_unicode());
        }
    }
    r
}

// 1:"username"
fn attr_string(attr: usize, msg: impl AsRef<str>) -> String {
    format!("{}:\"{}\"", attr, sanitize(msg))
}

// 4:194.109.6.66 or 15:8
fn attr_item(attr: usize, item: impl std::fmt::Display) -> String {
    format!("{}:{}", attr, item)
}

impl Datalog {

    // default or emoty?
    fn is_empty(&self) -> bool {
        self.time == SystemTime::UNIX_EPOCH &&
            self.src_ip.is_unspecified() &&
            self.username.as_str() == ""
    }

    // Generate 2 lines in "datalog" format.
    fn to_lines(&self) -> (String, String) {
        let mut request = Vec::new();
        let mut reply = Vec::new();

        // This will never fail, but _if_ it does, it simply
        // puts in the time/date of Towelday 2019.
        let time = self.time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(1558735200);
        let src_ip = match self.src_ip {
            IpAddr::V4(addr) => addr.to_string(),
            IpAddr::V6(addr) => addr.to_string(),
        };

        // request fields.
        request.push(time.to_string());
        request.push(src_ip.clone());
        request.push("1".to_string());
        request.push(attr_string(1, &self.username));
        request.push("2:\"\"".to_string());
        request.push(attr_item(4, &src_ip));
        if let Some(ref s) = self.callingsystem {
            request.push(attr_string(32, s));
        }
        if let Some(ref ip) = self.clientip {
            let ip = match ip {
                &IpAddr::V4(ref addr) => addr.to_string(),
                &IpAddr::V6(ref addr) => addr.to_string(),
            };
            request.push(attr_string(31, &ip));
        }

        // reply fields.
        reply.push(time.to_string());
        reply.push(src_ip);
        let reply_code = match self.status {
            Ok(_) => 2,
            Err(_) => 3,
        };
        reply.push(reply_code.to_string());
        if let Some(ref account) = self.account {
            if account != &self.username {
                reply.push(attr_string(1, account));
                reply.push(attr_xs401(25, account));
            }
        }
        // if no attrs pushed, add an empty attr (i.e. a comma).
        if reply.len() == 3 {
            reply.push("".to_string());
        }

        if let Err(ref e) = self.status {
            match self.message {
                Some(ref m) => reply.push(attr_string(24, m)),
                None => reply.push(attr_string(24, e.as_log_message())),
            }
            reply.push(attr_string(18, e.as_reply()));
        }

        // we're done.
        (request.as_slice().join(","), reply.as_slice().join(","))
    }

    /*
    // Remnant from when request.log was a Lua table instead of userdata.
    pub fn merge_rlua_table(&mut self, t: rlua::Table) -> Result<(), rlua::Error> {
        use std::str::FromStr;
        if t.contains_key("username")? {
            self.username = t.raw_get("username")?;
        }
        if let Some(ip) = t.raw_get::<_, Option<String>>("clientip")? {
            let ip = std::net::IpAddr::from_str(&ip).map_err(|e|
                rlua::Error::FromLuaConversionError {
                    from:   "string",
                    to:     "std::net::IpAddr",
                    message:    Some(e.to_string()),
                })?;
            self.clientip = Some(ip);
        }
        if t.contains_key("status")? {
            let status = t.raw_get::<_, usize>("status")?;
            self.status = Err(status.into());
        }
        self.callingsystem = t.raw_get("callingsystem")?;
        self.account = t.raw_get("account")?;
        self.message = t.raw_get("message")?;
        Ok(())
    }
    */
}

/// Enum used by the XS4ALL Radius code to define authentication errors.
/// We've just copied it verbatim to be as compatible as possible.
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types,dead_code)]
#[repr(C)]
pub(crate) enum Error {
    RQ_USERNAME,            /* No username in request           */
    RQ_PASSWD,              /* No password in request           */
    RQ_CIRCUIT,             /* No circuit in request            */
    RQ_IMSI,                /* No IMSI in request               */
    RQ_CALLERID,            /* No caller-id in request          */
    RQ_CHAP,                /* Chap request                     */
    BAD_USERNAME,           /* User not found                   */
    BAD_PASSWD,             /* Password incorrect               */
    UC_USERNAME,            /* uppercase letters in username    */
    NO_IPADDR,              /* Geen ip adres gevonden in export */
    NO_CIRCUIT,             /* Geen circuit gevonden in export  */
    WRONG_NRP,              /* Login vanaf verkeerde NRP        */
    WRONG_ENCAPS,           /* Wrong encapsulation              */
    DIALIN_BLACKLIST,       /* Caller-id blacklisted            */
    XSH_ABUSE,              /* XSH abuse shell op account       */
    XSH_NETIQUETTE,         /* XSH netiquette shell             */
    XSH_DELETED,            /* XSH deleted shell                */
    XSH_NOPAY,              /* XSH nopay shell                  */
    XSH_GENERIC,            /* XSH shell                        */
    INV_SHELL,              /* Other invalid shells             */
    INV_VANGPAGINA,         /* Invalid test vangpagina          */
    NO_SHELLHOST,           /* Kan shell host niet resolven     */
    NO_VLAN,                /* VLAN not found in vlan map       */
    WRONG_APN,              /* Mag niet op deze APN             */
    NO_OTPHOST,             /* OTP host does not resolve        */
    NO_OTPHOST_SECRET,      /* OTP host not in radiushosts      */
    OTP_SERVER_TIMEOUT,     /* OTP server antwoord niet         */
    DES_PASSWD,             /* DES passwords not accepted       */
    GENERIC,                /* Alle andere errors               */
}
use Error::*;

impl Error {
    fn count() -> usize {
        GENERIC as usize + 1
    }

    fn from_usize(num: usize) -> Error {
        match num {
            x if x == RQ_USERNAME as usize 		    => RQ_USERNAME,
            x if x == RQ_PASSWD as usize 			=> RQ_PASSWD,
            x if x == RQ_CIRCUIT as usize 		    => RQ_CIRCUIT,
            x if x == RQ_IMSI as usize 			    => RQ_IMSI,
            x if x == RQ_CALLERID as usize 		    => RQ_CALLERID,
            x if x == RQ_CHAP as usize 			    => RQ_CHAP,
            x if x == BAD_USERNAME as usize 		=> BAD_USERNAME,
            x if x == BAD_PASSWD as usize 		    => BAD_PASSWD,
            x if x == DES_PASSWD as usize 		    => DES_PASSWD,
            x if x == UC_USERNAME as usize 		    => UC_USERNAME,
            x if x == NO_IPADDR as usize 			=> NO_IPADDR,
            x if x == NO_CIRCUIT as usize       	=> NO_CIRCUIT,
            x if x == NO_VLAN as usize          	=> NO_VLAN,
            x if x == WRONG_NRP as usize        	=> WRONG_NRP,
            x if x == WRONG_APN as usize        	=> WRONG_APN,
            x if x == WRONG_ENCAPS as usize     	=> WRONG_ENCAPS,
            x if x == DIALIN_BLACKLIST as usize     => DIALIN_BLACKLIST,
            x if x == XSH_ABUSE as usize 			=> XSH_ABUSE,
            x if x == XSH_NETIQUETTE as usize 	    => XSH_NETIQUETTE,
            x if x == XSH_DELETED as usize 		    => XSH_DELETED,
            x if x == XSH_NOPAY as usize 			=> XSH_NOPAY,
            x if x == XSH_GENERIC as usize 		    => XSH_GENERIC,
            x if x == INV_SHELL as usize 			=> INV_SHELL,
            x if x == INV_VANGPAGINA as usize 	    => INV_VANGPAGINA,
            x if x == NO_SHELLHOST as usize 		=> NO_SHELLHOST,
            x if x == NO_OTPHOST as usize 		    => NO_OTPHOST,
            x if x == NO_OTPHOST_SECRET as usize    => NO_OTPHOST_SECRET,
            x if x == OTP_SERVER_TIMEOUT as usize   => OTP_SERVER_TIMEOUT,
            _          			                    => GENERIC,
        }
    }

    fn as_reply(&self) -> &'static str {
        match *self {
            RQ_USERNAME 		=> "No username in request",
            RQ_PASSWD 			=> "No password in request",
            RQ_CIRCUIT 			=> "No circuit in request",
            RQ_IMSI 			=> "No IMSI in request",
            RQ_CALLERID 		=> "No caller-id in request",
            RQ_CHAP 			=> "CHAP authentication not supported",
            BAD_USERNAME 		=> "Login incorrect",
            BAD_PASSWD 			=> "Login incorrect",
            DES_PASSWD 			=> "Login incorrect",
            UC_USERNAME 		=> "Uppercase letters in username",
            NO_IPADDR 			=> "No IP address found in database",
            NO_CIRCUIT       	=> "Circuit not found in database",
            NO_VLAN          	=> "VLAN not found in database",
            WRONG_NRP        	=> "Login from invalid NRP",
            WRONG_APN        	=> "Login from invalid APN",
            WRONG_ENCAPS     	=> "Wrong encapsulation",
            DIALIN_BLACKLIST   	=> "Login incorrect",
            XSH_ABUSE 			=> "Login incorrect",
            XSH_NETIQUETTE 		=> "Login incorrect",
            XSH_DELETED 		=> "Login incorrect",
            XSH_NOPAY 			=> "Login incorrect",
            XSH_GENERIC 		=> "Login incorrect",
            INV_SHELL 			=> "Login incorrect",
            INV_VANGPAGINA 		=> "Login incorrect",
            NO_SHELLHOST 		=> "Login incorrect",
            NO_OTPHOST 			=> "OTP server unavailable",
            NO_OTPHOST_SECRET   => "OTP server unavailable",
            OTP_SERVER_TIMEOUT  => "OTP server unavailable",
            _          				=> "Login incorrect",
        }
    }

    fn as_log_message(&self) -> &'static str {
        match *self {
            RQ_USERNAME         => "no username in request",
            RQ_PASSWD           => "no password in request",
            RQ_CIRCUIT          => "no circuit in request",
            RQ_IMSI             => "No IMSI in request",
            RQ_CALLERID         => "no caller-id in request",
            RQ_CHAP             => "CHAP authentication not supported",
            BAD_USERNAME        => "user unknown",
            BAD_PASSWD          => "password incorrect",
            DES_PASSWD          => "password invalid (DES)",
            UC_USERNAME         => "uppercase letters in username",
            NO_IPADDR           => "no IP address found in database",
            NO_CIRCUIT          => "circuit not found in database",
            NO_VLAN             => "VLAN not found in database",
            WRONG_NRP           => "login from invalid NRP",
            WRONG_APN           => "Login from invalid APN",
            WRONG_ENCAPS        => "wrong encapsulation",
            DIALIN_BLACKLIST	=> "blacklisted caller-id",
            XSH_ABUSE			=> "xsh-abuse shell",
            XSH_NETIQUETTE		=> "xsh-netiquette shell",
            XSH_DELETED     	=> "xsh-deleted shell",
            XSH_NOPAY       	=> "xsh-nopay shell",
            XSH_GENERIC     	=> "xsh shell",
            INV_SHELL       	=> "invalid shell",
            INV_VANGPAGINA  	=> "invalid vangpagina",
            NO_SHELLHOST    	=> "Shell host does not resolve",
            NO_OTPHOST      	=> "OTP host does not resolve",
            NO_OTPHOST_SECRET	=> "OTP host not in radiushosts",
            OTP_SERVER_TIMEOUT	=> "OTP server timeout",
            _		         		=> "login incorrect",
		}
    }
}

// integer -> variant.
impl From<usize> for Error {
    fn from(num: usize) -> Error {
        Error::from_usize(num)
    }
}

/// Iterate over all variants in the enum, returning the
/// variant, the usize value, and the name.
pub(crate) fn error_iter() -> impl Iterator<Item=(Error, usize, String)> {
    let mut count = 0;
    std::iter::from_fn(move || {
        if count < Error::count() {
            let c = count;
            count += 1;
            Some((Error::from(c), c, format!("{:?}", Error::from(c))))
        } else {
            None
        }
    })
}
