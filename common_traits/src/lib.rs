pub trait ByteCode {
    /// convert Element into Byte Array
    fn get_unique_byte_array(&self) -> Vec<u8>;
}

