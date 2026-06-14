/*
 * HackIT SQLi Data Extractor (Rust)
 * Binary search blind extraction, batch processing, and data reconstruction.
 */

use std::collections::HashMap;

/// Extract a single character via binary search over ASCII range
pub fn blind_extract_char(
    check_char_fn: &dyn Fn(usize, u8) -> bool,
    position: usize,
) -> Option<char> {
    let mut low = 32u8;
    let mut high = 126u8;
    let mut iterations = 0;

    while low < high && iterations < 10 {
        let mid = low + (high - low) / 2;
        iterations += 1;

        if check_char_fn(position, mid) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    if low >= 32 && low <= 126 {
        Some(low as char)
    } else {
        None
    }
}

/// Extract full string by iterating positions until failure
pub fn blind_extract_string(
    check_char_fn: &dyn Fn(usize, u8) -> bool,
    max_length: usize,
) -> String {
    let mut result = String::new();
    for pos in 1..=max_length {
        match blind_extract_char(check_char_fn, pos) {
            Some(c) => result.push(c),
            None => {
                if pos > 1 { break; }
            }
        }
    }
    result
}

/// Batch extract multiple columns from multiple rows
pub fn batch_extract(
    extract_fn: &dyn Fn(&str, usize, usize) -> Option<String>,
    columns: &[&str],
    row_count: usize,
) -> Vec<HashMap<String, String>> {
    let mut rows = Vec::new();
    for r in 0..row_count {
        let mut row = HashMap::new();
        for col in columns {
            if let Some(val) = extract_fn(col, r, 0) {
                row.insert(col.to_string(), val);
            }
        }
        if !row.is_empty() {
            rows.push(row);
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_extract_char() {
        // Mock: always return true for char 'A' (65) at position 1
        let checker = |pos: usize, mid: u8| -> bool {
            if pos == 1 {
                mid < 65
            } else {
                false
            }
        };
        assert_eq!(blind_extract_char(&checker, 1), Some('A'));
    }
}
