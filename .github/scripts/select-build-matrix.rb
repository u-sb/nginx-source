#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"

TARGETS = {
  "feature/openssl-4-test-pcre2" => [
    { distro: "debian", codename: "trixie",   osver: "13", version_schema: "new", variants: [] },
    { distro: "ubuntu", codename: "resolute", osver: "",   version_schema: "new", variants: [] }
  ],
  "master" => [
    # Debian 11 Bullseye    2021 - 2026-06 [EOF]
    { distro: "debian", codename: "bullseye", osver: "11", version_schema: "",    variants: [] },
    # Debian 12 Bookworm    2023 - 2028-06
    { distro: "debian", codename: "bookworm", osver: "12", version_schema: "new", variants: [] },

    # Ubuntu 20.04 Focal    2020 - 2025-06 [EOF]
    { distro: "ubuntu", codename: "focal",    osver: "",   version_schema: "",    variants: [] },
    # Ubuntu 22.04 Jammy    2022 - 2027-06
    { distro: "ubuntu", codename: "jammy",    osver: "",   version_schema: "",    variants: [] },
    # Ubuntu 24.04 Noble    2024 - 2029-06
    { distro: "ubuntu", codename: "noble",    osver: "",   version_schema: "new", variants: %w[amd64-v3] },
    # Ubuntu 25.04 Plucky   2025 - 2026-06 [EOF]
    { distro: "ubuntu", codename: "plucky",   osver: "",   version_schema: "new", variants: [] },
    # Ubuntu 25.10 Questing 2025 - 2026-12
    { distro: "ubuntu", codename: "questing", osver: "",   version_schema: "new", variants: [] }
  ],
  "master-pcre2" => [
    # Debian 13 Trixie      2025 - 2030-06
    { distro: "debian", codename: "trixie",   osver: "13", version_schema: "new", variants: %w[amd64-v3] },
    # Debian 14 Forky
    { distro: "debian", codename: "forky",    osver: "14", version_schema: "new", variants: [] },

    # Ubuntu 26.04 Resolute 2026 - 2031-06
    { distro: "ubuntu", codename: "resolute", osver: "",   version_schema: "new", variants: %w[amd64-v3] }
  ]
}.freeze

COMMON_VARIANTS = %w[arm64 amd64-v1]

RUNNERS = {
  "arm64" => "ubuntu-24.04-arm",
  "amd64-v1" => "ubuntu-24.04",
  "amd64-v3" => "ubuntu-24.04"
}.freeze

ISA_LEVELS = {
  "arm64" => "v1",
  "amd64-v1" => "v1",
  "amd64-v3" => "v3"
}.freeze

def artifact_name(codename, variant)
  case variant
  when "arm64"
    "arm64-#{codename}"
  when "amd64-v1"
    "amd64-#{codename}"
  when "amd64-v3"
    "amd64-#{codename}-v3"
  else
    raise "unknown variant: #{variant}"
  end
end

branch = ENV.fetch("GITHUB_REF_NAME") do
  warn "GITHUB_REF_NAME is not set"
  exit 2
end

targets = TARGETS.fetch(branch) do
  warn "unsupported branch for deb artifact build: #{branch}"
  exit 2
end

include = targets.flat_map do |target|
  (COMMON_VARIANTS + target.fetch(:variants)).map do |variant|
    {
      distro: target.fetch(:distro),
      codename: target.fetch(:codename),
      osver: target.fetch(:osver),
                                                           version_schema: target.fetch(:version_schema),
      artifact: artifact_name(target.fetch(:codename), variant),
      runner: RUNNERS.fetch(variant),
      isa: ISA_LEVELS.fetch(variant)
    }
  end
end

puts "include<<EOF"
puts JSON.generate(include)
puts "EOF"
