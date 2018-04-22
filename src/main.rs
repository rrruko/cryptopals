#![feature(entry_and_modify)]
#![feature(inclusive_range_syntax)]
#![feature(slice_patterns)]

extern crate byteorder;
extern crate itertools;
extern crate nalgebra as na;
#[macro_use]
extern crate nom;
extern crate rand;

mod aes;
mod blockmode;
mod codec;
mod mt;
mod oracle;
mod pkcs;
mod s_box;
mod stats;
mod xor;

mod set_1;
mod set_2;
mod set_3;

fn main() {
   set_1::set_1();
   set_2::set_2();
   set_3::set_3();
}
