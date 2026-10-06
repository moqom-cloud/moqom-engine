//! CRC-32C (Castagnoli), for archive records and object-store integrity.
//!
//! Castagnoli rather than the IEEE polynomial because it is what GCS reports in
//! `x-goog-hash` and verifies on upload, so one checksum covers both a torn
//! record on local disk and an object corrupted in transit. Table-driven and a
//! few lines, which is less than a dependency for it would be.

const POLYNOMIAL: u32 = 0x82F6_3B78;

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
};

/// A running checksum.
#[derive(Clone, Copy, Debug)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// An empty checksum.
    #[must_use]
    pub const fn new() -> Self {
        Self(!0)
    }

    /// Fold `bytes` in.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.0;
        for byte in bytes {
            crc = TABLE[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
        }
        self.0 = crc;
    }

    /// The checksum so far.
    #[must_use]
    pub const fn value(self) -> u32 {
        !self.0
    }
}

/// The checksum of `bytes`.
#[must_use]
pub fn checksum(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3720 §B.4 and the usual check value, so a wrong polynomial or a
    /// reflected table fails here rather than as GCS refusing every upload.
    #[test]
    fn the_standard_vectors() {
        assert_eq!(checksum(b"123456789"), 0xE306_9283);
        assert_eq!(checksum(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(checksum(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn incremental_matches_whole() {
        let mut running = Crc32c::new();
        running.update(b"1234");
        running.update(b"56789");
        assert_eq!(running.value(), checksum(b"123456789"));
    }
}
