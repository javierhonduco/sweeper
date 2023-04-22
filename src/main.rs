use core::sync::atomic::{AtomicBool, Ordering};
use libbpf_rs::{PerfBufferBuilder};
use rusqlite::{params, Connection, Result};
use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::ptr;
use std::time::Duration;
use std::{thread, time};
use sweeper::sweeper::SweeperSkelBuilder;

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
            runnable,
            sender,
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
                if let Ok(event) = recv.lock().unwrap().try_recv() {
                    conn.execute(
                        "INSERT INTO sweeper (path, name, expire_at) VALUES (?1, ?2, ?3)",
                        params![event.path, event.name, event.expire_at],
                    )
                    .unwrap();
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
        self.run_bpf(); // .unwrap();
        self.join_threads();

        Ok(())
    }

    pub fn join_threads(self) {
        for thread in self.threads {
            if let Err(e) = thread.join() {
                eprintln!("Error: {:?}", e);
                std::process::exit(1);
            }
        }
    }

    pub fn run_bpf(&self) {
        let skel_builder = SweeperSkelBuilder::default();
        let open_skel = skel_builder.open().unwrap();
        let mut bpf = open_skel.load().expect("bpf load");

        let perf_buffer = PerfBufferBuilder::new(bpf.maps().events())
            .sample_cb(|_cpu: i32, data: &[u8]| {
                self.on_event(data);
            })
            .lost_cb(|cpu, count| {
                eprintln!("Lost {} events on cpu {}", count, cpu)
            })
            .build().expect("perf buffer build");

        bpf.attach().expect("attach bpf program");

        let timeout: Duration = Duration::from_millis(200);
        while self.runnable.load(Ordering::SeqCst) {
            perf_buffer.poll(timeout).expect("perf buffer poll");
        }
    }

    fn on_event(&self, x: &[u8]) {
        println!("EVENT");
        let tx = self.sender.clone();
        unsafe {
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
        }
    }
}

fn delete(event: &Event) -> Result<()> {
    // Show drift?
    println!("🚮 Deleting {}", event.path);

    // Check that the file indeed has the expire_at xattr
    fs::remove_file(&event.path).unwrap();
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

    let sweeper = Sweeper::new(conn, cleaner_conn, runnable);
    if let Err(e) = sweeper.run() {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}
