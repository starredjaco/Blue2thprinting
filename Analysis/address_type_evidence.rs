// Fast address-type evidence reader for Sniffle DLT 256 classic pcaps.
// Usage: address_type_evidence <candidates> <newline-delimited pcap paths>
// Output: O<TAB>path<TAB>address<TAB>type<TAB>count<TAB>first<TAB>last,
// then F<TAB>path<TAB>ok or error for each input file.
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;

fn u32at(b: &[u8], o: usize, le: bool) -> u32 {
    let bytes: [u8; 4] = b[o..o + 4].try_into().unwrap();
    if le { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) }
}

fn address(b: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[5], b[4], b[3], b[2], b[1], b[0])
}

fn note(found: &mut HashMap<(String, u8), (u64, u32, u32)>, wanted: &HashSet<String>,
        bytes: &[u8], typ: u8, ts: u32) {
    if bytes.len() != 6 || typ > 3 { return; }
    let addr = address(bytes);
    if wanted.contains(&addr) {
        let row = found.entry((addr, typ & 1)).or_insert((0, ts, ts));
        row.0 += 1;
        row.1 = row.1.min(ts);
        row.2 = row.2.max(ts);
    }
}

fn le_event(params: &[u8], ts: u32, wanted: &HashSet<String>,
            found: &mut HashMap<(String, u8), (u64, u32, u32)>) {
    if params.len() < 2 { return; }
    let body = &params[1..];
    if body.is_empty() { return; }
    match params[0] {
        0x01 | 0x0a if body.len() >= 11 && body[0] == 0 =>
            note(found, wanted, &body[5..11], body[4], ts),
        0x02 => {
            let mut off = 1;
            for _ in 0..body[0] {
                if off + 10 > body.len() { break; }
                let size = body[off + 8] as usize;
                if off + 10 + size > body.len() { break; }
                note(found, wanted, &body[off + 2..off + 8], body[off + 1], ts);
                off += 10 + size;
            }
        }
        0x0b => {
            let mut off = 1;
            for _ in 0..body[0] {
                if off + 16 > body.len() { break; }
                note(found, wanted, &body[off + 2..off + 8], body[off + 1], ts);
                off += 16;
            }
        }
        0x0d => {
            let mut off = 1;
            for _ in 0..body[0] {
                if off + 24 > body.len() { break; }
                let size = body[off + 23] as usize;
                if off + 24 + size > body.len() { break; }
                note(found, wanted, &body[off + 3..off + 9], body[off + 2], ts);
                off += 24 + size;
            }
        }
        _ => {}
    }
}

fn scan_btsnoop(path: &str, data: &[u8], wanted: &HashSet<String>)
        -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 16 { return Err("short btsnoop header".into()); }
    let format = u32::from_be_bytes(data[12..16].try_into()?);
    if format != 1002 && format != 2001 { return Err("unsupported btsnoop format".into()); }
    let mut found = HashMap::new();
    let mut pos = 16;
    while pos + 24 <= data.len() {
        let len = u32::from_be_bytes(data[pos + 4..pos + 8].try_into()?) as usize;
        let flags = u32::from_be_bytes(data[pos + 8..pos + 12].try_into()?);
        let raw_ts = u64::from_be_bytes(data[pos + 16..pos + 24].try_into()?);
        pos += 24;
        if pos + len > data.len() { break; }
        let packet = &data[pos..pos + len];
        pos += len;
        let ts = match raw_ts.checked_sub(0x00dcddb30f2f8000) {
            Some(us) if (946684800..=4102444800).contains(&(us / 1_000_000)) =>
                (us / 1_000_000) as u32,
            _ => continue,
        };
        let event = if format == 1002 {
            if packet.first() != Some(&4) { continue; }
            &packet[1..]
        } else {
            if flags & 0xffff != 3 { continue; }
            packet
        };
        if event.len() < 2 || event.len() < 2 + event[1] as usize { continue; }
        let params = &event[2..2 + event[1] as usize];
        match event[0] {
            0x3e => le_event(params, ts, wanted, &mut found),
            0x03 if params.len() >= 9 => note(&mut found, wanted, &params[3..9], 0, ts),
            0x04 if params.len() >= 6 => note(&mut found, wanted, &params[..6], 0, ts),
            0x07 if params.len() >= 7 => note(&mut found, wanted, &params[1..7], 0, ts),
            _ => {}
        }
    }
    let mut rows: Vec<_> = found.into_iter().collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    for ((addr, typ), (count, first, last)) in rows {
        println!("O\t{path}\t{addr}\t{typ}\thci\t{count}\t{first}\t{last}");
    }
    Ok(())
}

fn scan(path: &str, wanted: &HashSet<String>) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    if data.starts_with(b"btsnoop\0") { return scan_btsnoop(path, &data, wanted); }
    if data.len() < 24 { return Err("short pcap header".into()); }
    let le = match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err("not a classic pcap".into()),
    };
    if u32at(&data, 20, le) != 256 { return Err("not DLT 256".into()); }
    let mut found: HashMap<(String, u8), (u64, u32, u32)> = HashMap::new();
    let mut pos = 24usize;
    while pos + 16 <= data.len() {
        let ts = u32at(&data, pos, le);
        let len = u32at(&data, pos + 8, le) as usize;
        pos += 16;
        // Sniffle captures interrupted mid-write can end with a partial
        // record. Earlier complete packets remain valid evidence.
        if pos + len > data.len() { break; }
        let p = &data[pos..pos + len];
        pos += len;
        if !(946684800..=4102444800).contains(&ts) || p.len() < 22 { continue; }
        let flags = u16::from_le_bytes([p[8], p[9]]);
        if (flags & 0x0400 != 0) && (flags & 0x0800 == 0) { continue; }
        if p[10..14] != [0xd6, 0xbe, 0x89, 0x8e] { continue; }
        let hdr = p[14];
        let pdu_type = hdr & 0x0f;
        let size = p[15] as usize;
        if p.len() < 16 + size + 3 { continue; }
        let body = &p[16..16 + size];
        let field = match pdu_type {
            0 | 1 | 2 | 4 | 6 if body.len() >= 6 => Some((&body[..6], (hdr >> 6) & 1)),
            3 | 5 if body.len() >= 12 => Some((&body[6..12], (hdr >> 7) & 1)),
            7 if body.len() >= 8 && (body[1] & 1 != 0) => Some((&body[2..8], (hdr >> 6) & 1)),
            _ => None,
        };
        if let Some((bytes, typ)) = field {
            note(&mut found, wanted, bytes, typ, ts);
        }
    }
    let mut rows: Vec<_> = found.into_iter().collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    for ((addr, typ), (count, first, last)) in rows {
        println!("O\t{path}\t{addr}\t{typ}\tair\t{count}\t{first}\t{last}");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 { return Err("usage: address_type_evidence <candidates> <path-list>".into()); }
    let wanted: HashSet<String> = fs::read_to_string(&args[1])?.lines().map(str::to_owned).collect();
    for path in fs::read_to_string(&args[2])?.lines() {
        match scan(path, &wanted) {
            Ok(()) => println!("F\t{path}\tok"),
            Err(error) => println!("F\t{path}\t{}", error.to_string().replace('\t', " ")),
        }
    }
    Ok(())
}
