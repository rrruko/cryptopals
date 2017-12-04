#![feature(slice_patterns)]

extern crate itertools;

mod codec;
mod stats;
mod xor;

mod set_1;

fn main() {
   set_1::set_1();
}