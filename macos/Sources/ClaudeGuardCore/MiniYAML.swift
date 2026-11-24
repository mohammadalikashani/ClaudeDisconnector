import Foundation

/// A small YAML reader for proxy-app configs: block maps and sequences (including
/// "- key: value" items), flow [lists] and {maps}, quoted / plain scalars, numbers,
/// booleans, comments and | / > block strings. Anchors, tags and multi-document
/// files aren't supported (proxy configs don't need them).
public enum MiniYAML {
    struct Line { var indent: Int; var text: String }

    public static func parse(_ text: String) -> Any? {
        var lines: [Line] = []
        for raw in text.replacingOccurrences(of: "\r", with: "").components(separatedBy: "\n") {
            if raw.trimmingCharacters(in: .whitespaces) == "---" { continue }
            let indent = raw.prefix(while: { $0 == " " }).count
            let body = stripComment(String(raw.dropFirst(indent))).trimmingCharacters(in: .whitespaces)
            lines.append(Line(indent: indent, text: body))   // keep blanks: block strings may need them
        }
        var i = 0
        skipBlank(lines, &i)
        guard i < lines.count else { return nil }
        return block(&lines, &i, lines[i].indent)
    }

    static func skipBlank(_ lines: [Line], _ i: inout Int) {
        while i < lines.count && lines[i].text.isEmpty { i += 1 }
    }

    /// Removes a "# comment" that isn't inside quotes.
    static func stripComment(_ s: String) -> String {
        var inS = false, inD = false
        var prev: Character = " "
        for (idx, c) in s.enumerated() {
            if c == "'" && !inD { inS.toggle() } else if c == "\"" && !inS { inD.toggle() }
            if c == "#" && !inS && !inD && (idx == 0 || prev == " " || prev == "\t") {
                return String(s.prefix(idx))
            }
            prev = c
        }
        return s
    }

    static func block(_ lines: inout [Line], _ i: inout Int, _ indent: Int) -> Any {
        skipBlank(lines, &i)
        guard i < lines.count else { return NSNull() }
        if lines[i].text == "-" || lines[i].text.hasPrefix("- ") { return seq(&lines, &i, lines[i].indent) }
        if splitKey(lines[i].text) != nil { return map(&lines, &i, indent) }
        let v = scalar(lines[i].text)
        i += 1
        return v
    }

    static func seq(_ lines: inout [Line], _ i: inout Int, _ indent: Int) -> [Any] {
        var out: [Any] = []
        while true {
            skipBlank(lines, &i)
            guard i < lines.count, lines[i].indent == indent, lines[i].text == "-" || lines[i].text.hasPrefix("- ") else { break }
            let rest = lines[i].text == "-" ? "" : String(lines[i].text.dropFirst(2)).trimmingCharacters(in: .whitespaces)
            if rest.isEmpty {
                i += 1
                skipBlank(lines, &i)
                out.append(i < lines.count && lines[i].indent > indent ? block(&lines, &i, lines[i].indent) : NSNull())
            } else if splitKey(rest) != nil && !rest.hasPrefix("{") && !rest.hasPrefix("[") && !rest.hasPrefix("\"") && !rest.hasPrefix("'") {
                // "- key: value": a map whose first entry sits on the dash line.
                let col = indent + (lines[i].text.count - rest.count)
                lines[i] = Line(indent: col, text: rest)
                out.append(map(&lines, &i, col))
            } else {
                out.append(scalar(rest))
                i += 1
            }
        }
        return out
    }

    static func map(_ lines: inout [Line], _ i: inout Int, _ indent: Int) -> [String: Any] {
        var out: [String: Any] = [:]
        while true {
            skipBlank(lines, &i)
            guard i < lines.count, lines[i].indent == indent, let (key, value) = splitKey(lines[i].text) else { break }
            i += 1
            if value == "|" || value == ">" || value.hasPrefix("|") || value.hasPrefix(">") {
                var parts: [String] = []
                while i < lines.count && (lines[i].indent > indent || lines[i].text.isEmpty) {
                    parts.append(lines[i].text)
                    i += 1
                }
                out[key] = parts.joined(separator: value.hasPrefix(">") ? " " : "\n")
            } else if value.isEmpty {
                skipBlank(lines, &i)
                if i < lines.count && (lines[i].indent > indent
                    || (lines[i].indent == indent && (lines[i].text == "-" || lines[i].text.hasPrefix("- ")))) {
                    out[key] = block(&lines, &i, lines[i].indent)
                } else {
                    out[key] = NSNull()
                }
            } else {
                out[key] = scalar(value)
            }
        }
        return out
    }

    /// "key: value" / "key:" (outside quotes and brackets) -> (key, value).
    static func splitKey(_ s: String) -> (String, String)? {
        var inS = false, inD = false, depth = 0
        let chars = Array(s)
        for (idx, c) in chars.enumerated() {
            if c == "'" && !inD { inS.toggle() } else if c == "\"" && !inS { inD.toggle() }
            if inS || inD { continue }
            if c == "[" || c == "{" { depth += 1 } else if c == "]" || c == "}" { depth -= 1 }
            if c == ":" && depth == 0 && (idx + 1 == chars.count || chars[idx + 1] == " ") {
                let key = unquote(String(chars[..<idx]).trimmingCharacters(in: .whitespaces))
                guard !key.isEmpty else { return nil }
                return (key, String(chars[(idx + 1)...]).trimmingCharacters(in: .whitespaces))
            }
        }
        return nil
    }

    static func unquote(_ s: String) -> String {
        if s.count >= 2, let f = s.first, f == "\"" || f == "'", s.last == f { return String(s.dropFirst().dropLast()) }
        return s
    }

    static func scalar(_ s: String) -> Any {
        if s.hasPrefix("[") || s.hasPrefix("{") {
            var idx = s.startIndex
            return flow(s, &idx)
        }
        if s.hasPrefix("\"") || s.hasPrefix("'") { return unquote(s) }
        switch s.lowercased() {
        case "true", "yes", "on": return true
        case "false", "no", "off": return false
        case "null", "~": return NSNull()
        default: break
        }
        if let n = Int(s) { return n }
        if let d = Double(s), s.contains(".") { return d }
        return s
    }

    /// Flow collections: [a, b, {k: v}] and {k: v, k2: [x]}.
    static func flow(_ s: String, _ idx: inout String.Index) -> Any {
        func skipSpace() { while idx < s.endIndex && (s[idx] == " " || s[idx] == "\t") { idx = s.index(after: idx) } }
        func token(_ stops: Set<Character>) -> String {
            skipSpace()
            if idx < s.endIndex, s[idx] == "\"" || s[idx] == "'" {
                let q = s[idx]
                idx = s.index(after: idx)
                let start = idx
                while idx < s.endIndex && s[idx] != q { idx = s.index(after: idx) }
                let t = String(s[start..<idx])
                if idx < s.endIndex { idx = s.index(after: idx) }
                return t
            }
            let start = idx
            while idx < s.endIndex && !stops.contains(s[idx]) { idx = s.index(after: idx) }
            return String(s[start..<idx]).trimmingCharacters(in: .whitespaces)
        }
        func value(_ stops: Set<Character>) -> Any {
            skipSpace()
            if idx < s.endIndex, s[idx] == "[" || s[idx] == "{" { return flow(s, &idx) }
            let quoted = idx < s.endIndex && (s[idx] == "\"" || s[idx] == "'")
            let t = token(stops)
            return quoted ? t : scalar(t)
        }
        guard idx < s.endIndex else { return NSNull() }
        if s[idx] == "[" {
            idx = s.index(after: idx)
            var out: [Any] = []
            while true {
                skipSpace()
                guard idx < s.endIndex else { break }
                if s[idx] == "]" { idx = s.index(after: idx); break }
                if s[idx] == "," { idx = s.index(after: idx); continue }
                out.append(value([",", "]"]))
            }
            return out
        }
        idx = s.index(after: idx)   // "{"
        var out: [String: Any] = [:]
        while true {
            skipSpace()
            guard idx < s.endIndex else { break }
            if s[idx] == "}" { idx = s.index(after: idx); break }
            if s[idx] == "," { idx = s.index(after: idx); continue }
            // key up to ": " (or ":" followed by end / flow char)
            var key = ""
            skipSpace()
            if s[idx] == "\"" || s[idx] == "'" {
                key = token([":"])
                skipSpace()
            } else {
                let start = idx
                while idx < s.endIndex {
                    if s[idx] == ":" {
                        let n = s.index(after: idx)
                        if n == s.endIndex || s[n] == " " || s[n] == "," || s[n] == "}" { break }
                    }
                    if s[idx] == "," || s[idx] == "}" { break }
                    idx = s.index(after: idx)
                }
                key = String(s[start..<idx]).trimmingCharacters(in: .whitespaces)
            }
            if idx < s.endIndex && s[idx] == ":" {
                idx = s.index(after: idx)
                out[key] = value([",", "}"])
            } else {
                out[key] = NSNull()
            }
        }
        return out
    }
}
