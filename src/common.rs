use std::io;
use std::mem::size_of;

/// Integer to Octet String primitive
pub fn i2osp(input: usize, length: usize) -> Vec<u8> {
    if length <= size_of::<usize>() {
        return (&input.to_be_bytes()[size_of::<usize>() - length..]).to_vec();
    }

    let mut output = vec![0u8; length];
    output.splice(
        length - std::mem::size_of::<usize>()..length,
        input.to_be_bytes().iter().cloned(),
    );
    output
}

pub fn xor(x: &[u8], y: &[u8]) -> io::Result<Vec<u8>> {
    if x.len() != y.len() {
        return Err(io::Error::from_raw_os_error(2));
    }
    Ok(x.iter().zip(y).map(|(&x1, &x2)| x1 ^ x2).collect())
}

/// I2OSP(len(input), max_bytes) || input
pub fn i2osp_serialize(input: &[u8], max_bytes: usize) -> Vec<u8> {
    [&i2osp(input.len(), max_bytes), input].concat()
}
