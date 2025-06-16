use std::fs::File;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Instant;

// 助手函数：从CSV文件读取数据
pub fn read_csv<P: AsRef<Path>>(path: P, delimiter: char) -> io::Result<Vec<Vec<String>>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut results = Vec::new();

    for line in reader.lines().skip(1) {
        // 跳过标题行
        let line = line?;
        let values: Vec<String> = line.split(delimiter).map(|s| s.to_string()).collect();
        results.push(values);
    }

    Ok(results)
}

// 解析日期为Unix时间戳
pub fn parse_date(date_str: &str) -> u64 {
    // 简化处理，实际应用中应使用日期解析库
    // 示例格式: 1989-12-03
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return 0;
    }

    let year = parts[0].parse::<u64>().unwrap_or(0);
    let month = parts[1].parse::<u64>().unwrap_or(0);
    let day = parts[2].parse::<u64>().unwrap_or(0);

    // 简单转换为天数
    year * 365 + month * 30 + day
}

// 解析日期时间为Unix时间戳
pub fn parse_datetime(datetime_str: &str) -> u64 {
    // 简化处理，实际应用中应使用日期时间解析库
    // 示例格式: 2010-02-14T15:32:10.447+0000
    if let Some(date_part) = datetime_str.split('T').next() {
        return parse_date(date_part);
    } else {
        panic!("Failed to parse datetime: {}", datetime_str);
    }
}

// 将名字字符串解析为有限域元素
pub fn parse_name_to_field(name: &str) -> u64 {
    if name.is_empty() {
        return 0;
    }

    // 基本的哈希方法：将字符串中每个字符的ASCII值相加，然后转换为域元素
    let mut sum: u64 = 0;
    let mut multiplier: u64 = 1;

    // 为了避免简单加法产生太多冲突，给每个字符位置一个不同的权重
    for c in name.bytes() {
        sum = sum.wrapping_add(multiplier.wrapping_mul(c as u64));
        multiplier = multiplier.wrapping_mul(31); // 使用质数31作为乘法因子
    }

    // 对大数进行简单的取模运算，避免溢出
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

#[cfg(test)]
mod tests {
    // 引入你需要测试的函数和必要的模块
    use super::*; // 引入父模块（包含你的函数）的所有内容
    use std::io::Write; // 用于写入临时文件
    use tempfile::NamedTempFile; // 使用 tempfile crate 来轻松创建临时文件

    // 测试 read_csv 函数
    #[test]
    fn test_read_csv() -> io::Result<()> {
        // 1. 创建一个临时的 CSV 文件
        let mut temp_file = NamedTempFile::new()?;
        // 写入 CSV 内容（包含标题行和数据行）
        writeln!(temp_file, "Header1,Header2,Header3")?;
        writeln!(temp_file, "r1c1,r1c2,r1c3")?;
        writeln!(temp_file, "r2c1,r2c2,r2c3")?;
        writeln!(temp_file, "r3c1,,r3c3")?; // 测试空字段

        // 2. 获取临时文件的路径
        let file_path = temp_file.path().to_path_buf();

        // 3. 调用 read_csv 函数
        let result = read_csv(&file_path, ',');

        // 4. 断言结果是否符合预期
        assert!(result.is_ok()); // 确保函数成功执行
        let data = result.unwrap();

        // 预期结果（注意：标题行被跳过）
        let expected_data: Vec<Vec<String>> = vec![
            vec!["r1c1".to_string(), "r1c2".to_string(), "r1c3".to_string()],
            vec!["r2c1".to_string(), "r2c2".to_string(), "r2c3".to_string()],
            vec!["r3c1".to_string(), "".to_string(), "r3c3".to_string()], // 空字段应为空字符串
        ];

        assert_eq!(data, expected_data); // 比较实际结果和预期结果

        // 5. 测试非逗号分隔符
        let mut temp_file_pipe = NamedTempFile::new()?;
        writeln!(temp_file_pipe, "Header1|Header2")?;
        writeln!(temp_file_pipe, "val1|val2")?;
        let file_path_pipe = temp_file_pipe.path().to_path_buf();
        let result_pipe = read_csv(&file_path_pipe, '|');
        assert!(result_pipe.is_ok());
        let data_pipe = result_pipe.unwrap();
        let expected_data_pipe: Vec<Vec<String>> =
            vec![vec!["val1".to_string(), "val2".to_string()]];
        assert_eq!(data_pipe, expected_data_pipe);

        // 6. 测试空文件（只有标题行）
        let mut temp_file_header_only = NamedTempFile::new()?;
        writeln!(temp_file_header_only, "Header1,Header2")?;
        let file_path_header_only = temp_file_header_only.path().to_path_buf();
        let result_header_only = read_csv(&file_path_header_only, ',');
        assert!(result_header_only.is_ok());
        assert!(result_header_only.unwrap().is_empty()); // 结果应为空 Vec

        // 7. 测试文件不存在的情况 (read_csv 本身会返回 Err，这里不用显式测试，除非你想捕获特定错误类型)
        // let result_nonexistent = read_csv("nonexistent_file.csv", ',');
        // assert!(result_nonexistent.is_err());

        Ok(()) // 表示测试成功完成
               // 临时文件会在 temp_file 离开作用域时自动删除
    }

    // 测试 parse_date 函数
    #[test]
    fn test_parse_date() {
        // 1. 测试有效日期
        // 计算预期值: year * 365 + month * 30 + day
        assert_eq!(parse_date("1989-12-03"), 1989 * 365 + 12 * 30 + 3);
        assert_eq!(parse_date("2023-01-01"), 2023 * 365 + 1 * 30 + 1);
        assert_eq!(parse_date("0000-01-01"), 0 * 365 + 1 * 30 + 1);
        assert_eq!(parse_date("2023-05-40"), 2023 * 365 + 5 * 30 + 40);
    }

    // 测试 parse_datetime 函数
    #[test]
    fn test_parse_datetime() {
        // 1. 测试有效日期时间字符串
        // 它应该只解析日期部分，结果与 parse_date 相同
        let expected_date_val = 2010 * 365 + 2 * 30 + 14;
        assert_eq!(
            parse_datetime("2010-02-14T15:32:10.447+0000"),
            expected_date_val
        );
        assert_eq!(
            parse_datetime("2010-02-14Tanything_else"),
            expected_date_val
        );

        // 2. 测试日期部分无效的日期时间字符串
        assert_eq!(parse_datetime("invalid-dateT10:00:00"), 0); // 调用 parse_date("invalid-date") 结果为 0
    }

    #[test]
    #[should_panic(expected = "Failed to parse datetime: ")] // 检查 panic 消息的一部分
    fn test_parse_datetime_panic_no_t() {
        // 这个字符串缺少 'T'，会导致 split('T').next() 后直接 panic
        parse_datetime("2010-02-14 15:32:10");
    }

    #[test]
    #[should_panic(expected = "Failed to parse datetime: ")]
    fn test_parse_datetime_panic_empty() {
        // 空字符串也会 panic
        parse_datetime("");
    }

    // 测试 parse_name_to_field 函数
    #[test]
    fn test_parse_name_to_field() {
        // 1. 测试基本名称
        // 手动计算或预先计算哈希值
        // "A" = 65
        // "B" = 66
        // "AB" = (65 * 1) + (66 * 31) = 65 + 2046 = 2111
        // "BA" = (66 * 1) + (65 * 31) = 66 + 2015 = 2081
        let modulus: u64 = (1 << 32) - 1; // 4294967295

        assert_eq!(parse_name_to_field("A"), 65 % modulus);
        assert_eq!(parse_name_to_field("B"), 66 % modulus);
        assert_eq!(parse_name_to_field("AB"), 2111 % modulus);
        assert_eq!(parse_name_to_field("BA"), 2081 % modulus);

        // 计算 "Alice" 的哈希
        // A=65, l=108, i=105, c=99, e=101
        // 65*1 + 108*31 + 105*31^2 + 99*31^3 + 101*31^4
        let mut sum_alice: u64 = 0;
        let mut multiplier_alice: u64 = 1;
        for c in "Alice".bytes() {
            sum_alice = sum_alice.wrapping_add(multiplier_alice.wrapping_mul(c as u64));
            multiplier_alice = multiplier_alice.wrapping_mul(31);
        }
        let expected_alice = sum_alice % modulus;
        assert_eq!(parse_name_to_field("Alice"), expected_alice);

        // 2. 测试空字符串
        assert_eq!(parse_name_to_field(""), 0);

        // 3. 测试包含非字母字符的名称
        let mut sum_test123: u64 = 0;
        let mut multiplier_test123: u64 = 1;
        for c in "Test123!".bytes() {
            sum_test123 = sum_test123.wrapping_add(multiplier_test123.wrapping_mul(c as u64));
            multiplier_test123 = multiplier_test123.wrapping_mul(31);
        }
        let expected_test123 = sum_test123 % modulus;
        assert_eq!(parse_name_to_field("Test123!"), expected_test123);

        // 4. 测试长字符串以检查 wrapping 行为 (结果需要手动计算或信任实现)
        let long_name = "a".repeat(100);
        let mut sum_long: u64 = 0;
        let mut multiplier_long: u64 = 1;
        for c in long_name.bytes() {
            sum_long = sum_long.wrapping_add(multiplier_long.wrapping_mul(c as u64));
            multiplier_long = multiplier_long.wrapping_mul(31);
        }
        let expected_long = sum_long % modulus;
        assert_eq!(parse_name_to_field(&long_name), expected_long);
    }
}
