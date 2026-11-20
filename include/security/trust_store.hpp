#pragma once
// The list of peers we trust, identified by the SHA-256 fingerprint of their certificate
// (the same idea as SSH's known_hosts). Plain text, one peer per line:
//
//     # comments and blank lines are ignored
//     3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b  alice

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace trust {

struct Entry {
    std::string fingerprint;   // always 64 lowercase hex characters
    std::string name;
};

// Accepts "AB:CD:..." or "abcd..." in any case (colons and spaces are ignored).
// Returns 64 lowercase hex characters, or nothing if the text is not a SHA-256 fingerprint.
std::optional<std::string> normalize_fingerprint(std::string_view text);

// "3a7b..." -> "3A:7B:..."  (how fingerprints are shown to people)
std::string display_fingerprint(const std::string& normalized);

// Names are shown in logs and stored in a text file, so keep them simple
bool valid_name(std::string_view name);

namespace detail {
std::string trim(std::string_view s);
} // namespace detail

// Reads the file's text. A line that is not understood grants NO trust; it is skipped, and
// described in `warnings` (when given) so a person can fix it.
std::vector<Entry> parse(std::string_view text, std::vector<std::string>* warnings = nullptr);

std::string serialize(const std::vector<Entry>& entries);

// The trust list stored in a file. The file is re-read every time it is asked something,
// so adding or removing a peer takes effect immediately, even in a running receiver.
class TrustStore {
public:
    explicit TrustStore(std::filesystem::path file);

    [[nodiscard]] const std::filesystem::path& path() const { return file_; }

    std::vector<Entry> list(std::vector<std::string>* warnings = nullptr) const;
    std::optional<std::string> find_name(const std::string& normalized_fingerprint) const;
    bool is_trusted(const std::string& normalized_fingerprint) const;

    // Each of these returns an error message, or an empty string on success
    std::string add(std::string_view fingerprint_text, std::string_view name) const;
    std::string remove(std::string_view who) const;

private:
    std::vector<Entry> read_unlocked(std::vector<std::string>* warnings) const;
    std::string write_unlocked(const std::vector<Entry>& entries) const;

    std::filesystem::path file_;
    mutable std::mutex mutex_;
};

} // namespace trust
