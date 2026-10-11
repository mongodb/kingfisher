//! Portable subprocess fixture for Docker CLI fallback tests.
use std::{env, fs, io::Write, process};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    assert_eq!(args.first().and_then(|arg| arg.to_str()), Some("image"));
    let operation = args.get(1).and_then(|arg| arg.to_str()).unwrap();
    let mut trace = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(env::var_os("KF_TEST_DOCKER_TRACE").unwrap())?;
    writeln!(trace, "{operation}")?;
    match operation {
        "inspect" => {
            assert_eq!(args.len(), 4);
            assert_eq!(args[2], "--");
            if env::var("KF_TEST_DOCKER_IMAGE_ABSENT").as_deref() == Ok("1") {
                eprintln!(
                    "Error response from daemon: No such image: {}",
                    args[3].to_string_lossy()
                );
                process::exit(1);
            }
        }
        "save" => {
            assert_eq!(args.len(), 6);
            assert_eq!(args[2], "-o");
            assert_eq!(args[4], "--");
            if env::var("KF_TEST_DOCKER_FAIL_SAVE").as_deref() == Ok("1") {
                fs::write(&args[3], b"partial archive")?;
                process::exit(1);
            }
            fs::copy(env::var_os("KF_TEST_DOCKER_ARCHIVE").unwrap(), &args[3])?;
        }
        _ => panic!("unexpected Docker CLI operation"),
    }
    Ok(())
}
