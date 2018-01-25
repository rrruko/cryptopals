#![feature(entry_and_modify)]
#![feature(inclusive_range_syntax)]
#![feature(slice_patterns)]

extern crate itertools;
extern crate nalgebra as na;
extern crate rand;

mod aes;
mod codec;
mod oracle;
mod pkcs;
mod s_box;
mod stats;
mod xor;

mod set_1;
mod set_2;

fn main() {
   //set_1::set_1();
   set_2::set_2();
}
