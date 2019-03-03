// ngxchash
// implementation of nginx chash algorithm

use std::cmp::{Ordering};
use std::fmt;

// CRC32Table
pub const CRC32_TABLE:[u32;256] = [
		0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
		0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
		0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
		0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
		0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
		0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
		0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
		0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
		0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
		0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
		0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
		0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
		0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
		0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
		0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
		0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
		0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
		0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
		0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
		0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
		0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
		0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
		0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
		0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
		0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
		0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
		0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
		0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
		0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
		0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
		0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
		0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
		0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
		0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
		0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
		0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
		0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
		0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
		0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
		0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
		0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
		0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
		0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
		0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
		0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
		0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
		0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
		0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
		0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
		0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
		0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
		0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
		0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
		0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
		0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
		0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
		0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
		0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
		0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
		0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
		0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
		0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
		0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
		0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
];

union Edian {
    hash: u32,
    bytes: [u8;4],
}

pub const CHASH_FACTOR:u32 = 160;
pub const CRC32_INIT:u32 = 0xffffffff;
pub const MAX_RETRIES:u32 = 20;

/*
#[warn(dead_code)] 
fn ngx_crc32_init() -> u32 {
    CRC32_INIT
}
*/

fn ngx_crc32_update(hash: u32, bs: &[u8], length: usize) -> u32 {
    let mut hash:u32 = hash;
    for i in 0..bs.len() {
        hash = CRC32_TABLE[((hash^(bs[i] as u32))&0xff) as usize] ^ (hash >> 8);
    }
    // '\0'
    for _ in bs.len()..length {
        hash = CRC32_TABLE[(hash^0&0xff) as u8 as usize] ^ (hash >> 8)
    }
    hash
}

fn ngx_crc32_final(hash: u32) -> u32 {
    hash^CRC32_INIT
}

fn ngx_crc32_prev(hash: u32) -> [u8;4] {
    if cfg!(target_edian = "little") {
        unsafe {
            let edian = Edian{hash: hash};
            edian.bytes
        }
    }else{
        let mut hashs:[u8;4] = [0,0,0,0];
        for _i in 0..4 {
            hashs[_i] = (hash >> (8 * _i as u32) as u32 & 0xff) as u8;
        }
        hashs
    }
}

pub fn ngx_crc32_long(s: &String, length:usize) -> u32 {
    ngx_crc32_final(ngx_crc32_update(CRC32_INIT, s.as_bytes(), length))
}

// Nginx Server's attr
#[derive(Clone)]
pub struct ServerS {
    pub server: String, // server name to caculate hash
    pub peer: String, // peer
    pub weight: u32, // config weight, to caculate hash
    pub effective_weight: u32, // effective weight
    pub max_conn: u32, // config max_conn
    pub curr_conn: u32, // curr conn
    pub hash: u32, // hash
    pub hit_count: u32, // statistic
    pub hit_rate: f32,
}

impl Default for ServerS {
    fn default() -> ServerS {
        ServerS{
            server: "".to_owned(),
            peer: "".to_owned(),
            weight: 0,
            effective_weight: 0,
            max_conn: 0,
            curr_conn: 0,
            hash: 0,
            hit_count: 0,
            hit_rate: 0_f32,
        }
    }
}

impl fmt::Debug for ServerS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ServerS {{server: {}, peer: {}, weight: {}, hit_count:{}, hit_rate:{} }}",
            self.server, self.peer, self.weight, self.hit_count, self.hit_rate)
    }
}

#[derive(Eq, Clone)]
pub struct HashPointS {
    pub server: String,
    pub hash: u32,
}

// for sort_by()
impl Ord for HashPointS {
    fn cmp(&self, other: &HashPointS) -> Ordering {
        self.hash.cmp(&other.hash)
    }
}

impl PartialOrd for HashPointS{
    fn partial_cmp(&self, other: &HashPointS) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HashPointS {
    fn eq(&self, other: &HashPointS) -> bool {
        self.hash == other.hash
    }
}

// for printf!()
impl fmt::Debug for HashPointS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HashPointS {{server: {:-15},hash: {:-10}}}", self.server, self.hash)
    }
}

pub fn ngx_chash_upstream(servers: &Vec<ServerS>) -> Vec<HashPointS>{
    let mut hashs:Vec<HashPointS> = Vec::new();

    for _i in 0..servers.len() {
        let mut _hashs = ngx_chash(&servers[_i].server, servers[_i].weight);
        hashs.append(&mut _hashs);
    }

    hashs.sort_by(|a,b| a.cmp(b));
    //println!("{:?}", hashs);
    remove_duplicate(&mut hashs);
    //println!("{:?}", hashs);

    hashs
}

pub fn ngx_chash(server: &String, weight: u32) -> Vec<HashPointS> {
    // TODO
    //  better implemation
    let mid:usize = server.find(":").unwrap();
    let host:String = server[..mid].to_owned();
    let port:String = server[mid+1..].to_owned();

    let mut hash:u32 = CRC32_INIT;

    // host
    hash = ngx_crc32_update(hash, host.as_bytes(), host.len());
    hash = ngx_crc32_update(hash, "".as_bytes(), 1);
    // port
    hash = ngx_crc32_update(hash, port.as_bytes(), port.len());

    let mut hashs:Vec<HashPointS> = Vec::with_capacity((CHASH_FACTOR*weight) as usize);
    let mut prev_hash:[u8;4] = [0, 0, 0, 0];
    for _ in 0..(CHASH_FACTOR*weight) as usize {
        let mut hash_tmp:u32 = hash;
        hash_tmp = ngx_crc32_update(hash_tmp, &prev_hash, 4);
        hash_tmp = ngx_crc32_final(hash_tmp);
        hashs.push(HashPointS{
            server: server.clone(),
            hash: hash_tmp,
        });
        //
        println!("server: {} -> hash: {} -> phash: {:?}", server, hash_tmp, prev_hash);
        prev_hash = ngx_crc32_prev(hash_tmp);
    }

    hashs
}

fn remove_duplicate(hashs: &mut Vec<HashPointS>) {
    //let (_hashs, _ ) = hashs.partition_dedup();

    let mut i:usize = 0;
    let mut j:usize = 1;
    let length: usize = hashs.len();
    while j < length {
        if hashs[i] != hashs[j] {
            i += 1;
            hashs.swap(i, j);
        }
        j += 1;
    }
    for _i in i+1..length {
        //
        hashs.pop();
    }
    //hashs
}

pub fn find_hash_point(hashs: &Vec<HashPointS>, hash: &HashPointS) -> HashPointS{
    match hashs.binary_search(hash) {
        Ok(index) => {
            hashs[index%hashs.len()].to_owned()
        },
        Err(index) => {
            hashs[index%hashs.len()].to_owned()
        }
    }
}

pub fn find_server(hashs: &Vec<HashPointS>, server: &String) -> HashPointS {
    let _hash_point = &HashPointS{
        server: server.clone(),
        hash: ngx_crc32_long(server, server.len()),
    };
    //println!("server: {}, hash: {}", server, _hash_point.hash);
    find_hash_point(hashs, _hash_point)
}

pub fn ngx_find_peer(upstream: &mut Vec<ServerS>, server_name: &String) -> ServerS {
    let mut server:ServerS = ServerS{..Default::default()};
    // TODO
    // failed -> max_conn -> server -> update effective_weight
    for i in 0..upstream.len(){
        if upstream[i].server.eq(server_name) {
            upstream[i].hit_count += 1;
            server = upstream[i].clone();
            break;
        }
    }
    server
}

#[test]
fn test_find_server(){

    let server = "192.168.0.1";
    assert_eq!(ngx_crc32_long(&server.to_owned(), server.len()), 2307365224);
    let server = "192.168.0.10";
    assert_eq!(ngx_crc32_long(&server.to_owned(), server.len()), 3074142674);

    let mut upstream:Vec<ServerS> = vec![
        ServerS{
            server: "127.0.0.1:8080".to_owned(),
            peer: "127.0.0.1:8080".to_owned(),
            weight: 1,
            ..Default::default()
        },
        ServerS{
            server: "127.0.0.1:443".to_owned(),
            peer: "127.0.0.1:443".to_owned(),
            weight: 2,
            ..Default::default()
        }
    ];
    let hashs = ngx_chash_upstream(&upstream);

    let _hash_point = find_server(&hashs, &"192.168.0.1".to_owned());
    assert_eq!(_hash_point.server, "127.0.0.1:443");
    assert_eq!(_hash_point.hash, 2315499649);

    let _hash_point = find_server(&hashs, &"192.168.0.10".to_owned());
    assert_eq!(_hash_point.server, "127.0.0.1:443");
    assert_eq!(_hash_point.hash, 3083802589);

    let _servers = ngx_find_peer(&mut upstream, &"127.0.0.1:443".to_owned());
    assert_eq!(_servers.peer, "127.0.0.1:443".to_owned());
}
