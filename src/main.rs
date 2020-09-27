use bcc::perf_event::PerfMapBuilder;
use bcc::{BccError, Tracepoint, BPF};
use core::sync::atomic::{AtomicBool, Ordering};
use rusqlite::{params, Connection, Result};
use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;
use std::{thread, time};

#[repr(C)]
struct event_t {
    path: [u8; 50],
    name: [u8; 50],
    value: [u8; 50],
}

#[derive(Debug)]
struct Event {
    id: i32,
    path: String,
    name: String,
    value: String,
    expire_at: i32,
}

fn on_event() -> Box<dyn FnMut(&[u8]) + Send> {
    // Panics in C callbacks are undefined behaviour. Here be dragons!
    Box::new(|x| unsafe {
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
        // Extract expire_at
        if name == "user.expire_at" {
            if &path[0..1] == "/" {
                println!("🧹🧹🧹🧹");
                persist(path, name, value).unwrap();
            } else {
                println!("🚮 Path must be absolute");
            }
        } else {
            println!("😴");
        }
    })
}

fn persist(path: &str, name: &str, value: &str) -> Result<()> {
    // Creating a connection per event :/
    let conn = Connection::open("test.db")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS sweeper (
        id INTEGER PRIMARY KEY,
        path TEXT NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        expire_at timestamp NOT NULL)",
        params![],
    )?;

    conn.execute(
        "INSERT INTO sweeper (path, name, value, expire_at) VALUES (?1, ?2, ?3, ?4)",
        params![path, name, value, value.parse::<i32>().unwrap()],
    )?;
    Ok(())
}

fn delete(event: &Event) -> Result<()> {
    println!("=> Deleting {:?}", event);

    // Check that the file indeed has the expire_at xattr
    fs::remove_file(event.path.to_string()).unwrap();
    Ok(())
}

fn clean_up(runnable: Arc<AtomicBool>) {
    let conn = Connection::open("test.db").unwrap();

    while runnable.load(Ordering::SeqCst) {
        let mut stmt = conn
            .prepare("SELECT * from sweeper where expire_at <= strftime('%s', 'now')")
            .unwrap();
        let sweep_iter = stmt
            .query_map(params![], |row| {
                Ok(Event {
                    id: row.get(0).unwrap(),
                    path: row.get(1).unwrap(),
                    name: row.get(2).unwrap(),
                    value: row.get(3).unwrap(),
                    expire_at: row.get(4).unwrap(),
                })
            })
            .unwrap();

        for sweep in sweep_iter {
            let thing = sweep.unwrap();
            // Make atomic
            conn.execute("DELETE FROM sweeper WHERE id = ?1", params![&thing.id])
                .unwrap();
            delete(&thing).unwrap();
        }

        thread::sleep(time::Duration::from_millis(100));
    }
}
fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let text = "
    #include <uapi/linux/ptrace.h>

    struct event_t {
        char path[50];
        char name[50];
        char value[50];
    };

    BPF_PERF_OUTPUT(events);

    int do_event(struct tracepoint__syscalls__sys_enter_lsetxattr *args) {
        struct event_t event = {0};
        // Try to extract PWD or the dentry
        bpf_probe_read_user_str(event.path, sizeof(event.path), args->pathname);
        // Check for expire_at
        bpf_probe_read_user_str(event.name, sizeof(event.name), args->name);
        bpf_probe_read_user_str(event.value, sizeof(event.value), args->value);

        // bpf_trace_printk(\"=path: %s\\n\", event.path);
        // bpf_trace_printk(\"=name: %s\\n\", event.name);
        // bpf_trace_printk(\"=value: %s\\n\", event.value);
        events.perf_submit(args, &event, sizeof(event));
        return 0;
    }

    // Submit the event in on successful return
    ";
    let mut bpf = BPF::new(text)?;
    Tracepoint::new()
        .handler("do_event")
        .subsystem("syscalls")
        .tracepoint("sys_enter_lsetxattr")
        .attach(&mut bpf)?;
    let events = bpf.table("events")?;
    let mut perf_buffer = PerfMapBuilder::new(events, on_event).build()?;
    while runnable.load(Ordering::SeqCst) {
        perf_buffer.poll(200);
    }
    Ok(())
}

fn main() {
    println!("~~ Sweeper 🧹🧹 ~~");

    // We need a Atomic Reference Count because ctrlc spawns a thread for
    // signal delivering
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("ctrlc");

    let rr = runnable.clone();
    let t = thread::spawn(move || clean_up(rr));
    match do_main(runnable) {
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
        _ => {}
    }

    let _ = t.join();
}
