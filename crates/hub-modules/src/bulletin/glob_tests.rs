use super::glob_match;

fn candidates(alphabet: &[char], maximum: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut level = all.clone();
    for _ in 0..maximum {
        level = level
            .iter()
            .flat_map(|prefix| {
                alphabet
                    .iter()
                    .map(move |letter| format!("{prefix}{letter}"))
            })
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

fn reference(pattern: &[u8], value: &[u8]) -> bool {
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    for letter in pattern {
        let mut next = vec![false; row.len()];
        next[0] = *letter == b'*' && row[0];
        for column in 1..row.len() {
            next[column] = if *letter == b'*' {
                row[column] || next[column - 1]
            } else {
                row[column - 1] && *letter == value[column - 1]
            };
        }
        row = next;
    }
    row[value.len()]
}

#[test]
fn glob_matches_small_pattern_reference() {
    for pattern in candidates(&['a', 'b', '*'], 5) {
        for value in candidates(&['a', 'b'], 5) {
            assert_eq!(
                glob_match(&pattern, &value),
                reference(pattern.as_bytes(), value.as_bytes()),
                "{pattern:?} / {value:?}"
            );
        }
    }
}

#[test]
fn glob_handles_long_ambiguous_patterns_and_unicode() {
    let pattern = format!("{}b*", "*a".repeat(64));
    assert!(!glob_match(&pattern, &"a".repeat(200_000)));
    assert!(glob_match("資料/*/é*", "資料/nested/path/éclair"));
    assert!(!glob_match("a*a", "a"));
    assert!(glob_match(&"*".repeat(100_000), ""));
}
