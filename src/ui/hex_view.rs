//! Forensic hexdump formatting engine and Shannon entropy calculator.
//!
//! Provides payload inspection capabilities for security incident payloads,
//! hexdump generation in standard forensic format, and Shannon entropy estimation.

/// Forensic hexdump generator and Shannon entropy payload analyzer.
#[allow(dead_code)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HexViewer;

#[allow(dead_code)]
impl HexViewer {
    /// Creates a new `HexViewer`.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }

    /// Formats a forensic hexdump for the given byte slice up to `max_lines`.
    ///
    /// Line format:
    /// `00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|`
    ///
    /// - Splits 16 bytes into two 8-byte chunks separated by double spaces.
    /// - Right column displays printable ASCII preview or `.` for non-printable characters.
    pub fn format_forensic_dump(data: &[u8], max_lines: usize) -> Vec<String> {
        if data.is_empty() || max_lines == 0 {
            return Vec::new();
        }

        let mut lines = Vec::new();
        for (i, chunk) in data.chunks(16).take(max_lines).enumerate() {
            let offset = i * 16;
            let mut line = format!("{:08x}  ", offset);

            // First 8-byte chunk
            let first_len = chunk.len().min(8);
            let first_chunk = &chunk[..first_len];
            for (j, &b) in first_chunk.iter().enumerate() {
                if j > 0 {
                    line.push(' ');
                }
                line.push_str(&format!("{:02x}", b));
            }
            if first_len < 8 {
                let missing = 8 - first_len;
                if first_len == 0 {
                    line.push_str(&" ".repeat(23));
                } else {
                    line.push_str(&" ".repeat(missing * 3));
                }
            }

            // Double space separating the two 8-byte chunks
            line.push_str("  ");

            // Second 8-byte chunk
            if chunk.len() > 8 {
                let second_chunk = &chunk[8..];
                for (j, &b) in second_chunk.iter().enumerate() {
                    if j > 0 {
                        line.push(' ');
                    }
                    line.push_str(&format!("{:02x}", b));
                }
                if second_chunk.len() < 8 {
                    let missing = 8 - second_chunk.len();
                    line.push_str(&" ".repeat(missing * 3));
                }
            } else {
                line.push_str(&" ".repeat(23));
            }

            // Double space before ASCII preview
            line.push_str("  |");

            // Printable ASCII preview or '.'
            for &b in chunk {
                if (0x20..=0x7e).contains(&b) {
                    line.push(b as char);
                } else {
                    line.push('.');
                }
            }
            line.push('|');

            lines.push(line);
        }

        lines
    }

    /// Calculates Shannon entropy of `data` (range: 0.0 to 8.0).
    ///
    /// Empty input returns 0.0.
    pub fn calculate_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0f32;

        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Returns a textual badge reflecting the entropy level:
    /// - `"[LOW]"` for entropy < 3.0
    /// - `"[MED]"` for entropy in [3.0, 6.0)
    /// - `"[HIGH/PACKED]"` for entropy >= 6.0
    pub fn entropy_badge(entropy: f32) -> &'static str {
        if entropy.is_nan() || entropy < 3.0 {
            "[LOW]"
        } else if entropy < 6.0 {
            "[MED]"
        } else {
            "[HIGH/PACKED]"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump_empty() {
        let _ = HexViewer::new();
        let empty_data: &[u8] = &[];
        assert!(HexViewer::format_forensic_dump(empty_data, 10).is_empty());
        assert!(HexViewer::format_forensic_dump(b"non-empty", 0).is_empty());
    }

    #[test]
    fn test_hexdump_exact_16_bytes() {
        let data = [
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let lines = HexViewer::format_forensic_dump(&data, 10);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|"
        );
        assert_eq!(lines[0].find('|'), Some(60));
    }

    #[test]
    fn test_hexdump_odd_length() {
        let data = b"Hello, World!";
        let lines = HexViewer::format_forensic_dump(data, 10);
        assert_eq!(lines.len(), 1);
        let expected = "00000000  48 65 6c 6c 6f 2c 20 57  6f 72 6c 64 21           |Hello, World!|";
        assert_eq!(lines[0], expected);
        assert_eq!(lines[0].find('|'), Some(60));

        let short_data = b"ABC";
        let short_lines = HexViewer::format_forensic_dump(short_data, 10);
        assert_eq!(short_lines.len(), 1);
        assert_eq!(
            short_lines[0],
            "00000000  41 42 43                                          |ABC|"
        );
        assert_eq!(short_lines[0].find('|'), Some(60));

        let multi = b"0123456789ABCDEFG";
        let multi_lines = HexViewer::format_forensic_dump(multi, 5);
        assert_eq!(multi_lines.len(), 2);
        assert_eq!(
            multi_lines[0],
            "00000000  30 31 32 33 34 35 36 37  38 39 41 42 43 44 45 46  |0123456789ABCDEF|"
        );
        assert_eq!(multi_lines[0].find('|'), Some(60));
        assert_eq!(
            multi_lines[1],
            "00000010  47                                                |G|"
        );
        assert_eq!(multi_lines[1].find('|'), Some(60));
    }

    #[test]
    fn test_entropy_calculation() {
        // Empty data has 0 entropy
        assert_eq!(HexViewer::calculate_entropy(&[]), 0.0);

        // Uniform single byte has 0 entropy
        let zeros = vec![0u8; 100];
        assert_eq!(HexViewer::calculate_entropy(&zeros), 0.0);
        assert_eq!(HexViewer::entropy_badge(0.0), "[LOW]");

        // Two equally likely values has entropy 1.0
        let mut two_vals = vec![b'A'; 50];
        two_vals.extend(vec![b'B'; 50]);
        let ent2 = HexViewer::calculate_entropy(&two_vals);
        assert!((ent2 - 1.0).abs() < 1e-4);
        assert_eq!(HexViewer::entropy_badge(ent2), "[LOW]");

        // English text typically has entropy ~3.5 - 4.5
        let text = b"The quick brown fox jumps over the lazy dog! Sentinela forensic analysis engine.";
        let text_entropy = HexViewer::calculate_entropy(text);
        assert!(text_entropy >= 3.0 && text_entropy < 6.0);
        assert_eq!(HexViewer::entropy_badge(text_entropy), "[MED]");

        // All 256 bytes present equally has max entropy 8.0
        let all_bytes: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let max_entropy = HexViewer::calculate_entropy(&all_bytes);
        assert!((max_entropy - 8.0).abs() < 1e-4);
        assert_eq!(HexViewer::entropy_badge(max_entropy), "[HIGH/PACKED]");
    }

    #[test]
    fn test_entropy_badge_thresholds() {
        assert_eq!(HexViewer::entropy_badge(0.0), "[LOW]");
        assert_eq!(HexViewer::entropy_badge(2.99), "[LOW]");
        assert_eq!(HexViewer::entropy_badge(3.0), "[MED]");
        assert_eq!(HexViewer::entropy_badge(5.99), "[MED]");
        assert_eq!(HexViewer::entropy_badge(6.0), "[HIGH/PACKED]");
        assert_eq!(HexViewer::entropy_badge(8.0), "[HIGH/PACKED]");
        assert_eq!(HexViewer::entropy_badge(f32::NAN), "[LOW]");
    }

    #[test]
    fn test_hexdump_max_lines_limit() {
        let data = vec![0x42; 64]; // 4 lines of 16 bytes
        let dump_1 = HexViewer::format_forensic_dump(&data, 1);
        assert_eq!(dump_1.len(), 1);

        let dump_2 = HexViewer::format_forensic_dump(&data, 2);
        assert_eq!(dump_2.len(), 2);

        let dump_all = HexViewer::format_forensic_dump(&data, 100);
        assert_eq!(dump_all.len(), 4);
    }
}
