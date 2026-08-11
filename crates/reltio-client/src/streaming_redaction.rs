use std::iter::Iterator;

const DECODE_VARIANTS: [DecodeVariant; 3] = [
    DecodeVariant::Json,
    DecodeVariant::Percent,
    DecodeVariant::Form,
];

#[derive(Clone, Copy)]
enum DecodeVariant {
    Json,
    Percent,
    Form,
}

pub(crate) fn inspect_canonical_bytes(bytes: &[u8], secrets: &[&str]) -> (bool, bool) {
    inspect_canonical_iter(&bytes.iter().copied(), secrets)
}

pub(crate) fn inspect_canonical_iter<I>(input: &I, secrets: &[&str]) -> (bool, bool)
where
    I: Clone + Iterator<Item = u8>,
{
    let patterns = SecretPatterns::new(secrets);
    let mut first_changed = [false; 3];
    for (index, variant) in DECODE_VARIANTS.into_iter().enumerate() {
        let mut decoded = CanonicalDecoder::new(I::clone(input), variant);
        let mut matcher = StreamingSecretMatcher::new(&patterns);
        for byte in decoded.by_ref() {
            if matcher.push(byte) {
                return (true, true);
            }
        }
        first_changed[index] = decoded.changed();
    }

    let mut fully_decoded = true;
    for (index, first_variant) in DECODE_VARIANTS.into_iter().enumerate() {
        if !first_changed[index] {
            continue;
        }
        for second_variant in DECODE_VARIANTS {
            let first = CanonicalDecoder::new(I::clone(input), first_variant);
            let mut second = CanonicalDecoder::new(first, second_variant);
            let mut matcher = StreamingSecretMatcher::new(&patterns);
            let mut decodable = DecodableSyntaxDetector::default();
            for byte in second.by_ref() {
                if matcher.push(byte) {
                    return (true, true);
                }
                decodable.push(byte);
            }
            if second.changed() && decodable.decodable {
                fully_decoded = false;
            }
        }
    }
    (false, fully_decoded)
}

struct CanonicalDecoder<I> {
    decoded: StreamingDecoder<I>,
    lossy_replay: Option<u8>,
    output: [u8; 4],
    output_offset: usize,
    output_len: usize,
    lossy_changed: bool,
}

impl<I> CanonicalDecoder<I> {
    fn new(input: I, variant: DecodeVariant) -> Self {
        Self {
            decoded: StreamingDecoder::new(input, variant),
            lossy_replay: None,
            output: [0; 4],
            output_offset: 0,
            output_len: 0,
            lossy_changed: false,
        }
    }

    fn changed(&self) -> bool {
        self.decoded.changed || self.lossy_changed
    }

    fn set_output(&mut self, bytes: &[u8]) {
        self.output[..bytes.len()].copy_from_slice(bytes);
        self.output_offset = 0;
        self.output_len = bytes.len();
    }
}

impl<I: Iterator<Item = u8>> Iterator for CanonicalDecoder<I> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.output_offset < self.output_len {
            let byte = self.output[self.output_offset];
            self.output_offset += 1;
            return Some(byte);
        }
        self.output_offset = 0;
        self.output_len = 0;
        if matches!(self.decoded.variant, DecodeVariant::Json) {
            return self.decoded.next();
        }
        let first = self.lossy_replay.take().or_else(|| self.decoded.next())?;
        if first.is_ascii() {
            return Some(first);
        }
        let Some(expected) = utf8_sequence_len(first) else {
            return Some(self.replacement());
        };
        let mut sequence = [0_u8; 4];
        sequence[0] = first;
        for (index, slot) in sequence.iter_mut().enumerate().take(expected).skip(1) {
            let Some(byte) = self.decoded.next() else {
                return Some(self.replacement());
            };
            if !valid_utf8_continuation(first, index, byte) {
                self.lossy_replay = Some(byte);
                return Some(self.replacement());
            }
            *slot = byte;
        }
        self.set_output(&sequence[1..expected]);
        Some(first)
    }
}

impl<I> CanonicalDecoder<I> {
    fn replacement(&mut self) -> u8 {
        self.lossy_changed = true;
        self.set_output(&[0xbf, 0xbd]);
        0xef
    }
}

fn utf8_sequence_len(first: u8) -> Option<usize> {
    match first {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

fn valid_utf8_continuation(first: u8, index: usize, byte: u8) -> bool {
    if index > 1 {
        return (0x80..=0xbf).contains(&byte);
    }
    match first {
        0xe0 => (0xa0..=0xbf).contains(&byte),
        0xed => (0x80..=0x9f).contains(&byte),
        0xf0 => (0x90..=0xbf).contains(&byte),
        0xf4 => (0x80..=0x8f).contains(&byte),
        _ => (0x80..=0xbf).contains(&byte),
    }
}

struct StreamingDecoder<I> {
    input: I,
    variant: DecodeVariant,
    replay: [u8; 24],
    replay_offset: usize,
    replay_len: usize,
    output: [u8; 4],
    output_offset: usize,
    output_len: usize,
    changed: bool,
}

impl<I> StreamingDecoder<I> {
    fn new(input: I, variant: DecodeVariant) -> Self {
        Self {
            input,
            variant,
            replay: [0; 24],
            replay_offset: 0,
            replay_len: 0,
            output: [0; 4],
            output_offset: 0,
            output_len: 0,
            changed: false,
        }
    }

    fn prepend_replay(&mut self, bytes: &[u8]) {
        let remaining = self.replay_len.saturating_sub(self.replay_offset);
        self.replay
            .copy_within(self.replay_offset..self.replay_len, bytes.len());
        self.replay[..bytes.len()].copy_from_slice(bytes);
        self.replay_offset = 0;
        self.replay_len = bytes.len() + remaining;
    }

    fn set_output(&mut self, bytes: &[u8]) {
        self.output[..bytes.len()].copy_from_slice(bytes);
        self.output_offset = 0;
        self.output_len = bytes.len();
    }
}

impl<I: Iterator<Item = u8>> Iterator for StreamingDecoder<I> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.output_offset < self.output_len {
            let byte = self.output[self.output_offset];
            self.output_offset += 1;
            return Some(byte);
        }
        self.output_offset = 0;
        self.output_len = 0;
        let byte = self.next_input()?;
        match self.variant {
            DecodeVariant::Json if byte == b'\\' => Some(self.decode_json_escape()),
            DecodeVariant::Form if byte == b'+' => {
                self.changed = true;
                Some(b' ')
            }
            DecodeVariant::Percent | DecodeVariant::Form if byte == b'%' => {
                Some(self.decode_percent_escape(byte))
            }
            DecodeVariant::Json | DecodeVariant::Percent | DecodeVariant::Form => Some(byte),
        }
    }
}

impl<I: Iterator<Item = u8>> StreamingDecoder<I> {
    fn next_input(&mut self) -> Option<u8> {
        if self.replay_offset < self.replay_len {
            let byte = self.replay[self.replay_offset];
            self.replay_offset += 1;
            Some(byte)
        } else {
            self.replay_offset = 0;
            self.replay_len = 0;
            self.input.next()
        }
    }

    fn decode_percent_escape(&mut self, original: u8) -> u8 {
        let mut consumed = [0_u8; 2];
        let mut count = 0_usize;
        while count < consumed.len() {
            let Some(byte) = self.next_input() else {
                break;
            };
            consumed[count] = byte;
            count += 1;
        }
        if count == 2 {
            if let (Some(high), Some(low)) = (hex_value(consumed[0]), hex_value(consumed[1])) {
                self.changed = true;
                return (high << 4) | low;
            }
        }
        self.prepend_replay(&consumed[..count]);
        original
    }

    fn decode_json_escape(&mut self) -> u8 {
        let Some(escaped) = self.next_input() else {
            return b'\\';
        };
        let simple = match escaped {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            b'/' => Some(b'/'),
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            _ => None,
        };
        if let Some(decoded) = simple {
            self.changed = true;
            return decoded;
        }
        if escaped != b'u' {
            self.prepend_replay(&[escaped]);
            return b'\\';
        }

        let mut consumed = [0_u8; 11];
        consumed[0] = escaped;
        let mut count = 1_usize;
        while count < 5 {
            let Some(byte) = self.next_input() else {
                self.prepend_replay(&consumed[..count]);
                return b'\\';
            };
            consumed[count] = byte;
            count += 1;
        }
        let Some(first) = decode_hex_quad(&consumed[1..5]) else {
            self.prepend_replay(&consumed[..count]);
            return b'\\';
        };
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            while count < consumed.len() {
                let Some(byte) = self.next_input() else {
                    self.prepend_replay(&consumed[..count]);
                    return b'\\';
                };
                consumed[count] = byte;
                count += 1;
            }
            if &consumed[5..7] != br"\u" {
                self.prepend_replay(&consumed[..count]);
                return b'\\';
            }
            let Some(second) = decode_hex_quad(&consumed[7..11]) else {
                self.prepend_replay(&consumed[..count]);
                return b'\\';
            };
            if !(0xdc00..=0xdfff).contains(&second) {
                self.prepend_replay(&consumed[..count]);
                return b'\\';
            }
            0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
        } else if (0xdc00..=0xdfff).contains(&first) {
            self.prepend_replay(&consumed[..count]);
            return b'\\';
        } else {
            u32::from(first)
        };
        let Some(character) = char::from_u32(scalar) else {
            self.prepend_replay(&consumed[..count]);
            return b'\\';
        };
        let mut encoded = [0_u8; 4];
        let encoded = character.encode_utf8(&mut encoded).as_bytes();
        self.changed = true;
        self.set_output(&encoded[1..]);
        encoded[0]
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_quad(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    bytes.iter().try_fold(0_u16, |value, byte| {
        Some((value << 4) | u16::from(hex_value(*byte)?))
    })
}

struct SecretPatterns<'a> {
    patterns: Vec<SecretPattern<'a>>,
}

struct SecretPattern<'a> {
    bytes: &'a [u8],
    prefix: Vec<usize>,
}

impl<'a> SecretPatterns<'a> {
    fn new(secrets: &'a [&'a str]) -> Self {
        let patterns = secrets
            .iter()
            .filter(|secret| !secret.is_empty())
            .map(|secret| {
                let bytes = secret.as_bytes();
                let mut prefix = vec![0_usize; bytes.len()];
                let mut matched = 0_usize;
                for index in 1..bytes.len() {
                    while matched > 0 && bytes[index] != bytes[matched] {
                        matched = prefix[matched - 1];
                    }
                    if bytes[index] == bytes[matched] {
                        matched += 1;
                    }
                    prefix[index] = matched;
                }
                SecretPattern { bytes, prefix }
            })
            .collect();
        Self { patterns }
    }
}

struct StreamingSecretMatcher<'a, 'patterns> {
    patterns: &'patterns SecretPatterns<'a>,
    matched: Vec<usize>,
}

impl<'a, 'patterns> StreamingSecretMatcher<'a, 'patterns> {
    fn new(patterns: &'patterns SecretPatterns<'a>) -> Self {
        Self {
            matched: vec![0; patterns.patterns.len()],
            patterns,
        }
    }

    fn push(&mut self, byte: u8) -> bool {
        for (pattern, matched) in self.patterns.patterns.iter().zip(&mut self.matched) {
            while *matched > 0 && byte != pattern.bytes[*matched] {
                *matched = pattern.prefix[*matched - 1];
            }
            if byte == pattern.bytes[*matched] {
                *matched += 1;
                if *matched == pattern.bytes.len() {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Default)]
struct DecodableSyntaxDetector {
    window: [u8; 12],
    offset: usize,
    len: usize,
    decodable: bool,
}

impl DecodableSyntaxDetector {
    fn push(&mut self, byte: u8) {
        if self.decodable {
            return;
        }
        self.window[self.offset] = byte;
        self.offset = (self.offset + 1) % self.window.len();
        self.len = self.len.saturating_add(1).min(self.window.len());
        self.decodable =
            byte == b'+' || self.percent_escape_ends_here() || self.json_escape_ends_here();
    }

    fn back(&self, distance: usize) -> u8 {
        self.window[(self.offset + self.window.len() - 1 - distance) % self.window.len()]
    }

    fn percent_escape_ends_here(&self) -> bool {
        self.len >= 3
            && self.back(2) == b'%'
            && self.back(1).is_ascii_hexdigit()
            && self.back(0).is_ascii_hexdigit()
    }

    fn json_escape_ends_here(&self) -> bool {
        if self.len >= 2
            && self.back(1) == b'\\'
            && matches!(
                self.back(0),
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
            )
        {
            return true;
        }
        if self.len >= 6 && self.back(5) == b'\\' && self.back(4) == b'u' {
            let quad = [self.back(3), self.back(2), self.back(1), self.back(0)];
            if decode_hex_quad(&quad).is_some_and(|value| !(0xd800..=0xdfff).contains(&value)) {
                return true;
            }
        }
        if self.len >= 12
            && self.back(11) == b'\\'
            && self.back(10) == b'u'
            && self.back(5) == b'\\'
            && self.back(4) == b'u'
        {
            let first = [self.back(9), self.back(8), self.back(7), self.back(6)];
            let second = [self.back(3), self.back(2), self.back(1), self.back(0)];
            return decode_hex_quad(&first).is_some_and(|value| (0xd800..=0xdbff).contains(&value))
                && decode_hex_quad(&second)
                    .is_some_and(|value| (0xdc00..=0xdfff).contains(&value));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::inspect_canonical_bytes;

    #[test]
    fn detects_cross_fragment_form_encoding() {
        assert_eq!(
            inspect_canonical_bytes(br#"["a+","b"]"#, &[r#"a ","b"#]),
            (true, true)
        );
    }

    #[test]
    fn distinguishes_stable_large_ordinary_encoding_syntax() {
        let body = format!(
            r#"{{"ordinary":"+","value":"{}"}}"#,
            "x".repeat(2 * 1024 * 1024)
        );
        assert_eq!(
            inspect_canonical_bytes(body.as_bytes(), &["unrelated-token"]),
            (false, true)
        );
    }

    #[test]
    fn detects_mixed_and_overdepth_encodings() {
        assert_eq!(
            inspect_canonical_bytes(br"secret\u00255Cu002dtoken", &["secret-token"]),
            (false, false)
        );
        assert_eq!(
            inspect_canonical_bytes(b"secret%25252Dtoken", &["secret-token"]),
            (false, false)
        );
    }

    #[test]
    fn percent_decoding_preserves_lossy_utf8_matching_semantics() {
        assert_eq!(inspect_canonical_bytes(b"%FF", &["�"]), (true, true));
        assert_eq!(inspect_canonical_bytes(b"%25FF", &["�"]), (true, true));
    }
}
