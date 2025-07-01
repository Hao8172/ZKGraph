use std::fs::File;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Instant;

pub fn read_csv<P: AsRef<Path>>(path: P, delimiter: char) -> io::Result<Vec<Vec<String>>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut results = Vec::new();

    for line in reader.lines().skip(1) {
        let line = line?;
        let values: Vec<String> = line.split(delimiter).map(|s| s.to_string()).collect();
        results.push(values);
    }

    Ok(results)
}
pub fn parse_date(date_str: &str) -> u64 {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return 0;
    }

    let year = parts[0].parse::<u64>().unwrap_or(0);
    let month = parts[1].parse::<u64>().unwrap_or(0);
    let day = parts[2].parse::<u64>().unwrap_or(0);
    year * 365 + month * 30 + day
}


pub fn parse_datetime(datetime_str: &str) -> u64 {
    if let Some(date_part) = datetime_str.split('T').next() {
        return parse_date(date_part);
    } else {
        panic!("Failed to parse datetime: {}", datetime_str);
    }
}

pub fn parse_name_to_field(name: &str) -> u64 {
    if name.is_empty() {
        return 0;
    }

    let mut sum: u64 = 0;
    let mut multiplier: u64 = 1;

    for c in name.bytes() {
        sum = sum.wrapping_add(multiplier.wrapping_mul(c as u64));
        multiplier = multiplier.wrapping_mul(31);
    }
    let modulus: u64 = (1 << 32) - 1;
    let result: u64 = sum % modulus;

    result
}

pub fn string_to_u64(s: &str) -> u64 {
    let mut result = 0;

    for (i, c) in s.chars().enumerate() {
        result += (i as u64 + 1) * (c as u64);
    }

    result
}

pub fn ipv4_to_u64(ip: &str) -> u64 {
    let ip_addr: Ipv4Addr = ip.parse().ok().unwrap();

    let octets = ip_addr.octets();

    u32::from_be_bytes(octets) as u64
}
