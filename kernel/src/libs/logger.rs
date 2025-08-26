use log::{Level, Record, set_logger, set_max_level};
use log::{LevelFilter, Log, Metadata};

#[unsafe(no_mangle)]
extern "C" fn rust_logger_init() {
    set_logger(&Logger).unwrap();
    set_max_level(LevelFilter::Trace);
}

struct Logger;

impl Logger {
    fn log_message(&self, record: &Record, with_location: bool) {
        if with_location {
            let file = record.file().unwrap();
            let line = record.line().unwrap();
            crate::println!("[{}] {}, {}:{}", record.level(), record.args(), file, line);
        } else {
            crate::println!("[{}] {}", record.level(), record.args());
        }
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let with_location = matches!(record.level(), Level::Debug);
            self.log_message(record, with_location);
        }
    }

    fn flush(&self) {}
}
