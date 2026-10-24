use std::error::Error as StdError;
use std::ops::{Deref, DerefMut};

use image::{EncodableLayout, ImageBuffer, Pixel};

//data to be encoded / decoded.

const HEADER_MAGIC: [u8; 8] = [b'A', b't', b'e', b'g', 0, 0, 0, 0];
struct Header {
    size: u64,
    check_sum: [u8; 16],
}
impl Header {
    fn new_for_data(data: &[u8]) -> Self {
        Header {
            size: data.len() as u64,
            check_sum: StegData::check_sum(data),
        }
    }
    fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        let len: [u8; 8] = <[u8; 8]>::try_from(&bytes[8..16]).unwrap();
        let check_sum: [u8; 16] = <[u8; 16]>::try_from(&bytes[16..32]).unwrap();
        return Self {
            size: u64::from_le_bytes(len),
            check_sum: check_sum,
        };
    }
    fn byte_at(&self, index: u64) -> u8 {
        if index < 8 {
            return HEADER_MAGIC[index as usize];
        } else if index < 16 {
            return self.size.to_le_bytes()[index as usize - 8];
        } else {
            return self.check_sum[index as usize - 16];
        }
    }
}

pub struct StegData {
    header: Header,
    data: Box<[u8]>,
}
impl StegData {
    const HEADER_LENGTH: u64 = 32;
    fn len(&self) -> u64 {
        self.data.len() as u64 + Self::HEADER_LENGTH
    }
    fn len_bits(&self) -> u64 {
        self.len() * 8
    }
    pub fn new(data: &[u8]) -> Self {
        Self {
            header: Header::new_for_data(data),
            data: data.into(),
        }
    }
    fn check_sum(data: &[u8]) -> [u8; 16] {
        let mut state: u128 = 0u128.into();
        let (chunks, rem) = data.as_chunks();
        for c in chunks {
            state ^= u128::from_le_bytes(*c);
        }
        let mut last: [u8; 16] = 0u128.to_le_bytes();

        for (i, x) in rem.iter().enumerate() {
            last[i] = *x;
        }

        state ^= u128::from_le_bytes(last);
        state.to_le_bytes()
    }
    pub fn get_data(&self) -> &[u8] {
        return &self.data;
    }
    fn index(&self, index: u64) -> u8 {
        if index < Self::HEADER_LENGTH {
            self.header.byte_at(index)
        } else {
            self.data[(index - Self::HEADER_LENGTH) as usize]
        }
    }
}
#[derive(Debug)]
pub enum Error {
    InvalidCheckSum,
    ImageTooSmall,
    MagicMismatch,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidCheckSum => f.write_str("Invalid checksum."),
            Error::ImageTooSmall => f.write_str("Image too small for expected data"),
            Error::MagicMismatch => f.write_str(
                "The magic number doesn't match. Are you sure the image contains steg data?",
            ),
        }
    }
}
impl StdError for Error {}

pub trait Steganography<T> {
    ///Encodes the data contained in steg_data into image
    fn encode<P: Pixel<Subpixel = T>, C: Deref<Target = [P::Subpixel]> + DerefMut>(
        &self,
        data: &StegData,
        image: &mut ImageBuffer<P, C>,
    ) -> Result<(), Error>;

    ///Decodes the data from image and returns it
    fn decode<P: Pixel<Subpixel = T>, C: Deref<Target = [P::Subpixel]>>(
        &self,
        image: &ImageBuffer<P, C>,
    ) -> Result<StegData, Error>;
}

pub struct LeastBit {}

impl LeastBit {}

impl Steganography<u8> for LeastBit {
    fn encode<P: Pixel<Subpixel = u8>, C: Deref<Target = [P::Subpixel]> + DerefMut>(
        &self,
        data: &StegData,
        image: &mut ImageBuffer<P, C>,
    ) -> Result<(), Error> {
        let bits_per_pixel = P::CHANNEL_COUNT as u64;
        let required_pixels = (data.len_bits() - 1 + bits_per_pixel) / bits_per_pixel;
        let pixels = {
            let (h, w) = image.dimensions();
            h as u64 * w as u64
        };

        if pixels < required_pixels {
            return Err(Error::ImageTooSmall);
        }

        const MASK: u8 = 0b1111_1110;
        let mut ind = 0;
        for p in image.pixels_mut() {
            for c in p.channels_mut() {
                let shift = ind % 8;
                let i = ind / 8;
                let x = data.index(i);
                //change last bit to bit from data
                *c = (*c & MASK) | ((x >> shift) & 1);

                ind += 1;
                if ind / 8 >= data.len() {
                    break;
                }
            }
            if ind / 8 >= data.len() {
                break;
            }
        }

        Ok(())
    }

    fn decode<P: Pixel<Subpixel = u8>, C: Deref<Target = [P::Subpixel]>>(
        &self,
        image: &ImageBuffer<P, C>,
    ) -> Result<StegData, Error> {
        let mut bytes = vec![];
        let mut shifts = 0;
        let mut data: u8 = 0;
        for p in image.pixels() {
            for c in p.channels() {
                let bit = *c & 1u8;
                data |= bit << shifts;
                shifts += 1;

                if shifts == 8 {
                    bytes.push(data);
                    shifts = 0;
                    data = 0;
                }
            }
        }

        if bytes[..8] != HEADER_MAGIC {
            return Err(Error::MagicMismatch);
        }
        let header = Header::from_bytes_unchecked(&bytes[..32]);
        let data = &bytes[32..(32 + header.size as usize)];
        let sd = StegData::new(data);
        if sd.header.size != header.size {
            return Err(Error::ImageTooSmall);
        }
        if sd.header.check_sum != header.check_sum {
            return Err(Error::InvalidCheckSum);
        }

        Ok(sd)
    }
}
#[cfg(test)]
mod test {
    use super::Error;
    use super::Steganography;
    use image::Luma;
    use image::{ImageBuffer, Rgb};

    use crate::steg::{LeastBit, StegData};

    const TMP_DIR: &str = "./test_img/";

    #[test]
    fn simple_round_trip() -> Result<(), Error> {
        let mut img = ImageBuffer::from_fn(8, 11 + 32, |_, _| Luma([0u8]));
        let data = "Hello Steg!".as_bytes();
        LeastBit {}.encode(&StegData::new(data), &mut img)?;
        let unstegged = LeastBit {}.decode(&img)?;

        assert_eq!(*data, *unstegged.data, "The roundtrip is mismatched");

        Ok(())
    }

    #[test]
    fn png_round_trip() -> Result<(), Error> {
        let path = TMP_DIR.to_owned() + "round_trip.png";
        let mut img = ImageBuffer::from_fn(8, 15, |_, _| Rgb([0u8; 3]));
        let data = "Hello Steg!".as_bytes();
        LeastBit {}.encode(&StegData::new(data), &mut img)?;

        img.save(&path).unwrap();
        let new_img = image::open(path).unwrap().into_rgb8();

        let unstegged = LeastBit {}.decode(&new_img)?;

        assert_eq!(*data, *unstegged.data, "The roundtrip is mismatched");

        Ok(())
    }
}
