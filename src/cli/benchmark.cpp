#include "benchmark.h"

#include "KdfProfiles.h"

#include <botan/mem_ops.h>
#include <botan/pwdhash.h>

#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Run Argon2id for one profile and return elapsed seconds.
double benchmarkProfile(const KdfProfileParams& p)
{
    auto pwdhash_fam = Botan::PasswordHashFamily::create("Argon2id");
    if (!pwdhash_fam) {
        throw std::runtime_error("Argon2id not available in this Botan build");
    }
    auto pwdhash = pwdhash_fam->from_params(p.m_kib, p.t, p.p);

    constexpr std::string_view benchmarkPassword  = "benchmark";
    constexpr size_t            salt_len  = 32;
    constexpr size_t            key_len   = 32;
    // Zero salt is intentional: Argon2id timing depends only on m/t/p, not on salt value.
    const uint8_t               salt[salt_len] = {};
    uint8_t                     key[key_len]   = {};

    const auto t0 = std::chrono::high_resolution_clock::now();
    pwdhash->derive_key(key, key_len,
                        benchmarkPassword.data(), benchmarkPassword.size(),
                        salt, salt_len);
    const auto t1 = std::chrono::high_resolution_clock::now();

    // Scrub key material immediately — it is meaningless but good practice.
    Botan::secure_scrub_memory(key, key_len);

    const std::chrono::duration<double> elapsed = t1 - t0;
    return elapsed.count();
}

} // namespace

namespace cli {

int cmd_benchmark()
{
    struct Row {
        const char* label;
        uint32_t    m_mib;
        uint32_t    t;
        uint32_t    p;
        double      seconds = 0.0;
        std::string error;
    };

    // Profile list ordered for display.
    constexpr std::array<EKDFProfile, 4> order = {
        EKDFProfile::Browser,
        EKDFProfile::Fast,
        EKDFProfile::Standard,
        EKDFProfile::High,
    };

    std::vector<Row> rows;
    rows.reserve(order.size());
    for (EKDFProfile id : order) {
        const KdfProfileParams* p = getProfileParams(id);
        if (!p) { continue; }
        Row r;
        r.label = p->name;
        r.m_mib = p->m_kib / 1024;
        r.t     = p->t;
        r.p     = p->p;
        try {
            r.seconds = benchmarkProfile(*p);
        } catch (const std::exception& ex) {
            r.error = ex.what();
        }
        rows.push_back(r);
    }

    // Print table header.
    std::cout << "\n";
    std::cout << std::left  << std::setw(16) << "Profile"
              << std::right << std::setw(9)  << "m (MiB)"
              << std::setw(4) << "t"
              << std::setw(4) << "p"
              << std::setw(8) << "Time"
              << "\n";
    std::cout << std::string(42, '-') << "\n";

    for (const auto& r : rows) {
        std::cout << std::left  << std::setw(16) << r.label
                  << std::right << std::setw(9)  << r.m_mib
                  << std::setw(4) << r.t
                  << std::setw(4) << r.p;
        if (r.error.empty()) {
            std::cout << std::setw(7) << std::fixed << std::setprecision(1) << r.seconds << "s";
        } else {
            std::cout << "  ERROR: " << r.error;
        }
        std::cout << "\n";
    }
    std::cout << "\n";

    return EXIT_SUCCESS;
}

} // namespace cli
