use hisi_rf_ws63::{SelectedProfile, Storage};

fn main() {
    let storage = Storage::<SelectedProfile, 4>::new();
    let mut output = String::new();
    storage
        .report()
        .write_json(&mut output)
        .expect("String writes are infallible");
    println!("{output}");
}
