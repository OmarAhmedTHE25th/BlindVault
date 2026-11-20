#include "trust_store.hpp"

#include <cctype>
#include <fstream>
#include <sstream>

namespace trust {

std::optional<std::string> normalize_fingerprint(std::string_view text) {
    std::string out;
    for (char c : text) {
        const auto uc = static_cast<unsigned char>(c);
        if (c == ':' || c == ' ') continue;
        if (!std::isxdigit(uc)) return std::nullopt;
        out.push_back(static_cast<char>(std::tolower(uc)));
    }
    if (out.size() != 64) return std::nullopt;
    return out;
}

std::string display_fingerprint(const std::string& normalized) {
    std::string out;
    for (std::size_t i = 0; i < normalized.size(); ++i) {
        if (i > 0 && i % 2 == 0) out.push_back(':');
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(normalized[i]))));
    }
    return out;
}

bool valid_name(std::string_view name) {
    if (name.empty() || name.size() > 64) return false;
    for (char c : name) {
        const auto uc = static_cast<unsigned char>(c);
        if (!(std::isalnum(uc) || c == '.' || c == '_' || c == '-')) return false;
    }
    return true;
}

namespace detail {
std::string trim(std::string_view s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}
} // namespace detail

std::vector<Entry> parse(std::string_view text, std::vector<std::string>* warnings) {
    std::vector<Entry> entries;
    std::istringstream in{std::string(text)};
    std::string raw;
    int line_number = 0;
    auto warn = [&](const std::string& message) {
        if (warnings) warnings->push_back("line " + std::to_string(line_number) + ": " + message);
    };
    while (std::getline(in, raw)) {
        ++line_number;
        const std::string line = detail::trim(raw);
        if (line.empty() || line[0] == '#') continue;

        const std::size_t split = line.find_first_of(" \t");
        if (split == std::string::npos) { warn("expected '<fingerprint> <name>'"); continue; }
        const auto fingerprint = normalize_fingerprint(line.substr(0, split));
        const std::string name = detail::trim(line.substr(split));
        if (!fingerprint) { warn("not a valid SHA-256 fingerprint"); continue; }
        if (!valid_name(name)) { warn("invalid name (use letters, digits, '.', '_' or '-')"); continue; }

        bool duplicate = false;
        for (const Entry& existing : entries) {
            if (existing.fingerprint == *fingerprint) duplicate = true;
        }
        if (duplicate) { warn("this fingerprint is already listed above, ignoring"); continue; }
        entries.push_back({*fingerprint, name});
    }
    return entries;
}

std::string serialize(const std::vector<Entry>& entries) {
    std::string out = "# Peers I trust: <SHA-256 fingerprint> <name>\n";
    for (const Entry& e : entries) out += e.fingerprint + "  " + e.name + "\n";
    return out;
}

TrustStore::TrustStore(std::filesystem::path file) : file_(std::move(file)) {}

std::vector<Entry> TrustStore::list(std::vector<std::string>* warnings) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return read_unlocked(warnings);
}

std::optional<std::string> TrustStore::find_name(const std::string& normalized_fingerprint) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const Entry& e : read_unlocked(nullptr)) {
        if (e.fingerprint == normalized_fingerprint) return e.name;
    }
    return std::nullopt;
}

bool TrustStore::is_trusted(const std::string& normalized_fingerprint) const {
    return find_name(normalized_fingerprint).has_value();
}

std::string TrustStore::add(std::string_view fingerprint_text, std::string_view name) const {
    const auto fingerprint = normalize_fingerprint(fingerprint_text);
    if (!fingerprint) return "that is not a SHA-256 fingerprint (expected 64 hex digits)";
    if (!valid_name(name)) return "invalid name (1 to 64 characters: letters, digits, '.', '_' or '-')";

    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Entry> entries = read_unlocked(nullptr);
    for (const Entry& e : entries) {
        if (e.fingerprint == *fingerprint) return "that fingerprint is already trusted, as '" + e.name + "'";
        if (e.name == name) return "the name '" + e.name + "' is already used by another peer";
    }
    entries.push_back({*fingerprint, std::string(name)});
    return write_unlocked(entries);
}

std::string TrustStore::remove(std::string_view who) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Entry> entries = read_unlocked(nullptr);
    const auto fingerprint = normalize_fingerprint(who);
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->name == who || (fingerprint && it->fingerprint == *fingerprint)) {
            entries.erase(it);
            return write_unlocked(entries);
        }
    }
    return "no trusted peer matches '" + std::string(who) + "'";
}

std::vector<Entry> TrustStore::read_unlocked(std::vector<std::string>* warnings) const {
    std::ifstream in(file_, std::ios::binary);
    if (!in) return {};
    std::ostringstream text;
    text << in.rdbuf();
    return parse(text.str(), warnings);
}

std::string TrustStore::write_unlocked(const std::vector<Entry>& entries) const {
    std::filesystem::path temp = file_;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) return "cannot write " + temp.string();
        out << serialize(entries);
        out.flush();
        if (!out) return "cannot write " + temp.string();
    }
    std::error_code ec;
    std::filesystem::rename(temp, file_, ec);
    if (ec) return "cannot update " + file_.string() + ": " + ec.message();
    return "";
}

} // namespace trust
