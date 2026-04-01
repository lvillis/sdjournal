mod fsprg;
mod key;
mod verify;

use hmac::Hmac;
use sha2::Sha256;

pub(crate) use self::fsprg::FsprgParams;
pub(crate) use self::key::parse_verification_key;
pub(crate) use self::verify::verify_file_seal;

type HmacSha256 = Hmac<Sha256>;

const FSPRG_RECOMMENDED_SECPAR: u16 = 1536;
const FSPRG_RECOMMENDED_SEEDLEN: usize = 96 / 8;

const RND_GEN_P: u32 = 0x01;
const RND_GEN_Q: u32 = 0x02;
const RND_GEN_X: u32 = 0x03;

const TAG_LENGTH: usize = 256 / 8;
const VERIFY_READ_CHUNK_SIZE: usize = 64 * 1024;
