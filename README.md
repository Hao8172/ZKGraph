This project requires Rust and its package manager, Cargo.

You can run any of the programs defined in the `src/bin/` directory using Cargo, like
```sh
cargo run --bin ic1 --release
```

To run these programs with different datasets, manually modify the relevant files in the src/bin/ directory. 

You will need to update the dataset file path and its corresponding k variable to one of the following pairs: 60k (k=16), 120k (k=17), or 180k (k=18). After saving your changes, compile and run the binary as usual.
