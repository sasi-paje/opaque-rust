use sha2::Sha512;
use digest::generic_array::typenum::Unsigned;
use digest::BlockInput;

pub use digest::Digest;

pub type Hash = Sha512;

pub trait HashSizing {
    fn output_size_usize() -> usize;
    fn block_size_usize() -> usize;
}

impl HashSizing for Hash {
    fn output_size_usize() -> usize {
        <Self as Digest>::OutputSize::to_usize()
    }

    fn block_size_usize() -> usize {
        <Self as BlockInput>::BlockSize::to_usize()
    }
}
