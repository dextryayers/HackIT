pub struct WordlistGenerator;

impl WordlistGenerator {
    pub fn number_append(base: &[String], max: u32) -> Vec<String> {
        let mut out = Vec::new();
        for word in base {
            for i in 0..=max {
                out.push(format!("{}{}", word, i));
            }
        }
        out
    }

    pub fn year_append(base: &[String], start: u16, end: u16) -> Vec<String> {
        let mut out = Vec::new();
        for word in base {
            for year in start..=end {
                out.push(format!("{}{}", word, year));
            }
        }
        out
    }

    pub fn capitalize(base: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for word in base {
            if let Some(c) = word.chars().next() {
                let cap: String = c.to_uppercase().to_string() + &word[1..];
                out.push(cap);
                out.push(word.to_uppercase());
                out.push(word.to_lowercase());
            }
        }
        out
    }

    pub fn leet_speak(word: &str) -> Vec<String> {
        let mut out = vec![word.to_string()];
        let leet_map: Vec<(char, &str)> = vec![
            ('a', "4"), ('A', "4"), ('e', "3"), ('E', "3"),
            ('i', "1"), ('I', "1"), ('o', "0"), ('O', "0"),
            ('s', "5"), ('S', "5"), ('t', "7"), ('T', "7"),
        ];
        for (ch, replacement) in &leet_map {
            if word.contains(*ch) {
                out.push(word.replace(*ch, replacement));
            }
        }
        out
    }

    pub fn common_suffixes(base: &[String]) -> Vec<String> {
        let suffixes = ["!", "@", "#", "$", "%", "123", "123!", "123@", "2023", "2024", "2025", "2026"];
        let mut out = Vec::new();
        for word in base {
            for sf in &suffixes {
                out.push(format!("{}{}", word, sf));
            }
        }
        out
    }

    pub fn expand(base: &[String], max_digits: u32, _years: bool) -> Vec<String> {
        let mut out: Vec<String> = base.to_vec();
        out.extend(Self::capitalize(base));
        out.extend(Self::number_append(base, max_digits));
        out.extend(Self::common_suffixes(base));
        out.sort();
        out.dedup();
        out
    }
}
