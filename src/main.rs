use bcc::perf_event::PerfMapBuilder;
use bcc::{BPFBuilder, BccError, Tracepoint};
use core::sync::atomic::{AtomicBool, Ordering};
use rusqlite::{params, Connection, Result};
use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::ptr;
use std::{thread, time};

use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

#[repr(C)]
struct event_t {
    path: [u8; 50],
    name: [u8; 50],
    value: [u8; 50],
}

#[derive(Debug)]
struct Event {
    id: Option<i32>,
    path: String,
    name: String,
    expire_at: i32,
}

struct Sweeper {
    conn: Arc<Mutex<Connection>>,
    cleaner_conn: Arc<Mutex<Connection>>,
    runnable: Arc<AtomicBool>,
    sender: std::sync::mpsc::Sender<Event>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<Event>>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Sweeper {
    pub fn new(
        connection: Connection,
        cleaner_connection: Connection,
        runnable: Arc<AtomicBool>,
    ) -> Self {
        let (sender, receiver) = channel();
        Sweeper {
            conn: Arc::new(Mutex::new(connection)),
            cleaner_conn: Arc::new(Mutex::new(cleaner_connection)),
            runnable: runnable,
            sender: sender,
            receiver: Arc::new(Mutex::new(receiver)),
            threads: Vec::new(),
        }
    }
    pub fn setup_db(&self) {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "CREATE TABLE IF NOT EXISTS sweeper (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            name TEXT NOT NULL,
            expire_at timestamp NOT NULL)",
                params![],
            )
            .unwrap();
    }

    pub fn setup_cleaner(&mut self) {
        let runnable = self.runnable.clone();
        let conn = self.cleaner_conn.clone();

        let t = thread::spawn(move || clean_up(conn, runnable));
        self.threads.push(t);
    }

    fn process(&mut self) {
        let recv = self.receiver.clone();
        let runnable = self.runnable.clone();
        let conn = self.conn.clone();

        let t = thread::spawn(move || {
            let conn = conn.lock().unwrap();

            while runnable.load(Ordering::SeqCst) {
                match recv.lock().unwrap().try_recv() {
                    Ok(event) => {
                        conn.execute(
                            "INSERT INTO sweeper (path, name, expire_at) VALUES (?1, ?2, ?3)",
                            params![event.path, event.name, event.expire_at],
                        )
                        .unwrap();
                    }
                    Err(_) => (),
                }

                thread::sleep(time::Duration::from_millis(100));
            }
        });

        self.threads.push(t);
    }
    pub fn run(mut self) -> Result<(), &'static str> {
        self.setup_db();
        self.setup_cleaner();
        self.process();
        // todo: propagate BccError
        self.run_bpf().unwrap();
        self.join_threads();

        Ok(())
    }

    pub fn join_threads(self) {
        for thread in self.threads {
            match thread.join() {
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    std::process::exit(1);
                }
                _ => {
                    // Nothing to do here
                }
            }
        }
    }

    pub fn run_bpf(&self) -> Result<(), BccError> {
        let text = "
        #include <uapi/linux/ptrace.h>

        struct event_t {
            char path[50];
            char name[50];
            char value[50];
        };

        BPF_HASH(storage, u64, struct event_t);
        BPF_PERF_OUTPUT(events);

        // Try to extract PWD or the dentry
        int set_attr_enter(struct tracepoint__syscalls__sys_enter_lsetxattr *args) {
            struct event_t event = {0};

            // We could validate them here for speed
            bpf_probe_read_user_str(event.path, sizeof(event.path), args->pathname);
            bpf_probe_read_user_str(event.name, sizeof(event.name), args->name);
            bpf_probe_read_user_str(event.value, sizeof(event.value), args->value);

            // bpf_trace_printk(\"=path: %s\\n\", event.path);
            // bpf_trace_printk(\"=name: %s\\n\", event.name);
            // bpf_trace_printk(\"=value: %s\\n\", event.value);

            u64 key = bpf_get_current_pid_tgid();
            storage.insert(&key, &event);
            return 0;
        }

        int set_attr_exit(struct tracepoint__syscalls__sys_exit_lsetxattr *args) {
            if (args->ret != 0) {
                return 1;
            }

            u64 key = bpf_get_current_pid_tgid();
            struct event_t* event = storage.lookup(&key);
            if (event == NULL) {
                return 1;
            }
            events.perf_submit(args, event, sizeof(struct event_t));
            storage.delete(&key);
            return 0;
        }
        ";
        let mut bpf = BPFBuilder::new(text).unwrap().build()?;
        Tracepoint::new()
            .handler("set_attr_enter")
            .subsystem("syscalls")
            .tracepoint("sys_enter_lsetxattr")
            .attach(&mut bpf)?;
        Tracepoint::new()
            .handler("set_attr_exit")
            .subsystem("syscalls")
            .tracepoint("sys_exit_lsetxattr")
            .attach(&mut bpf)?;
        Tracepoint::new()
            .handler("set_attr_enter")
            .subsystem("syscalls")
            .tracepoint("sys_enter_setxattr")
            .attach(&mut bpf)?;
        Tracepoint::new()
            .handler("set_attr_exit")
            .subsystem("syscalls")
            .tracepoint("sys_exit_setxattr")
            .attach(&mut bpf)?;
        let events = bpf.table("events")?;

        let mut perf_buffer = PerfMapBuilder::new(events, || self.on_event()).build()?;
        while self.runnable.load(Ordering::SeqCst) {
            perf_buffer.poll(200);
        }
        Ok(())
    }

    fn on_event(&self) -> Box<dyn FnMut(&[u8]) + Send> {
        let tx = self.sender.clone();
        Box::new(move |x| unsafe {
            let data = ptr::read(x.as_ptr() as *const event_t);

            let path = CStr::from_ptr(data.path.as_ptr() as *const c_char)
                .to_str()
                .unwrap();
            let name = CStr::from_ptr(data.name.as_ptr() as *const c_char)
                .to_str()
                .unwrap();
            let value = CStr::from_ptr(data.value.as_ptr() as *const c_char)
                .to_str()
                .unwrap();

            println!("📅 Event: (path={}, name={}, value={})", path, name, value);

            if name == "user.expire_at" {
                if &path[0..1] == "/" {
                    println!("╰ 🧹 Scheduled for deletion");
                    tx.send(Event {
                        id: None,
                        path: path.to_string(),
                        name: name.to_string(),
                        expire_at: value.parse::<i32>().unwrap(),
                    })
                    .unwrap();
                } else {
                    println!("╰ 🚮 Path must be absolute");
                }
            } else {
                println!("╰ 😴 setattr's name should be `user.expire_at`");
            }
        })
    }
}

fn delete(event: &Event) -> Result<()> {
    // Show drift?
    println!("🚮 Deleting {}", event.path);

    // Check that the file indeed has the expire_at xattr
    fs::remove_file(event.path.to_string()).unwrap();
    Ok(())
}

fn clean_up(conn: Arc<Mutex<Connection>>, runnable: Arc<AtomicBool>) {
    let conn = conn.lock().unwrap();

    while runnable.load(Ordering::SeqCst) {
        let mut stmt = conn
            .prepare("SELECT * from sweeper where expire_at <= strftime('%s', 'now')")
            .unwrap();

        let sweep_iter = stmt
            .query_map(params![], |row| {
                Ok(Event {
                    id: Some(row.get(0).unwrap()),
                    path: row.get(1).unwrap(),
                    name: row.get(2).unwrap(),
                    expire_at: row.get(3).unwrap(),
                })
            })
            .unwrap();

        for sweep in sweep_iter {
            let thing = sweep.unwrap();
            // Make atomic
            // Maybe mark as deleted
            conn.execute("DELETE FROM sweeper WHERE id = ?1", params![&thing.id])
                .unwrap();
            delete(&thing).unwrap();
        }

        thread::sleep(time::Duration::from_millis(100));
    }
}

fn main() {
    println!("🧹🧹🧹🧹 Sweeper 🧹🧹🧹🧹");

    let conn = Connection::open("test.db").unwrap();
    let cleaner_conn = Connection::open("test.db").unwrap();

    // We need a Atomic Reference Count because ctrlc spawns a thread for
    // signal delivering
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("ctrlc");

    let sweeper = Sweeper::new(conn, cleaner_conn, runnable.clone());
    match sweeper.run() {
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
        _ => {}
    }
}
